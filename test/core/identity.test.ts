/**
 * Identity protection: typosquatting and repository-squatting (SPEC 12, 23.1).
 *
 * SPEC 12.4 says the thresholds are initial heuristics that "must be calibrated
 * against true-positive and false-positive corpora before stable release". The
 * false-positive corpus below is therefore not decoration: a similarity check
 * that flags ordinary dependencies gets switched off, and a check that is
 * switched off protects nobody.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import {
  compareIdentifiers,
  damerauLevenshtein,
  normalizedDistance,
  normalizeIdentifier,
} from "../../src/analyzers/similarity.ts";
import {
  compareToProtected,
  compareToProtectedOwners,
  parseModuleIdentity,
} from "../../src/analyzers/repository.ts";
import {
  countIdentities,
  EMPTY_CORPUS,
  loadTrustCorpus,
  parseTrustDocument,
  similarityThreshold,
} from "../../src/core/trust.ts";
import { createRuntime } from "../../src/index.ts";

const tempRoots: string[] = [];

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

// ---------------------------------------------------------------------------
// The algorithm (SPEC 12.3, 22)
// ---------------------------------------------------------------------------

test("Damerau-Levenshtein counts an adjacent transposition as one edit", () => {
  assert.equal(damerauLevenshtein("uuid", "uuid"), 0);
  assert.equal(damerauLevenshtein("uuid", "uudi"), 1, "a transposition, not two substitutions");
  assert.equal(damerauLevenshtein("stripe", "stipe"), 1, "a deletion");
  assert.equal(damerauLevenshtein("stripe", "sttripe"), 1, "a duplicated character");
  assert.equal(damerauLevenshtein("google", "gooogle"), 1);
  assert.equal(damerauLevenshtein("", "abc"), 3);
  assert.equal(damerauLevenshtein("abc", ""), 3);
  assert.equal(damerauLevenshtein("kitten", "sitting"), 3, "the classic");
});

test("the distance is symmetric and normalizes against the longer string", () => {
  assert.equal(damerauLevenshtein("testify", "testfy"), damerauLevenshtein("testfy", "testify"));
  assert.equal(normalizedDistance("abcd", "abcd"), 0);
  assert.equal(normalizedDistance("abcd", "abce"), 0.25);
  assert.equal(normalizedDistance("", ""), 0);
});

test("separators and case are noise a squatter relies on", () => {
  assert.equal(normalizeIdentifier("Go-Redis"), "goredis");
  assert.equal(normalizeIdentifier("go_redis"), "goredis");

  const verdict = compareIdentifiers("go-redis", "goredis", 0.08);
  assert.equal(verdict.similar, true);
  assert.equal(verdict.signal, "separator-variant");
});

// SPEC 12.3: one edit in a four-letter name is a normalized distance of 0.25,
// which no sane threshold catches — yet it is exactly the pair that matters.
test("short identifiers are compared by absolute distance", () => {
  const short = compareIdentifiers("gorm", "gonm", 0.08);
  assert.equal(short.similar, true);
  assert.equal(short.signal, "short-identifier");

  assert.equal(compareIdentifiers("gorm", "xxxx", 0.08).similar, false, "two edits is not a typo");
});

test("the profile widens the net rather than changing the verdict", () => {
  assert.equal(similarityThreshold("standard"), 0.08);
  assert.equal(similarityThreshold("hardened"), 0.15);
  assert.equal(similarityThreshold("paranoid"), 0.25);

  // One edit in an eleven-character name: 0.09, between standard and hardened.
  assert.equal(compareIdentifiers("cloudflare", "cloudfIare", 0.08).similar, false);
  assert.equal(compareIdentifiers("cloudflare", "cloudfIare", 0.15).similar, true);
});

// ---------------------------------------------------------------------------
// Component-aware identity (SPEC 12.2, 12.5)
// ---------------------------------------------------------------------------

test("a module path is split into host, owner, repository and subpath", () => {
  assert.deepEqual(parseModuleIdentity("github.com/google/uuid"), {
    canonical: "github.com/google/uuid",
    host: "github.com",
    owner: "google",
    repository: "uuid",
  });
  assert.deepEqual(parseModuleIdentity("github.com/aws/aws-sdk-go-v2/service/s3").subpath, "service/s3");
  // A major-version directory belongs to the version, not the name.
  assert.equal(parseModuleIdentity("github.com/foo/bar/v2").canonical, "github.com/foo/bar");
  assert.equal(parseModuleIdentity("github.com/foo/bar/v2").repository, "bar");
});

const UUID = { module: "github.com/google/uuid" };

// SPEC 12.5: the strongest signal has the LARGEST edit distance.
test("the protected repository name under a different owner is a repository squat", () => {
  const hit = compareToProtected("github.com/random-owner/uuid", UUID, 0.08);
  assert.equal(hit?.signal, "repository-squat");
  assert.match(hit?.message ?? "", /under a different owner/);
});

test("a typo in the owner of a protected module is caught", () => {
  const hit = compareToProtected("github.com/gooogle/uuid", UUID, 0.08);
  assert.equal(hit?.signal, "repository-squat", "same repo, different owner: the stronger signal");
});

test("a typo in the repository of a protected module is caught", () => {
  const hit = compareToProtected("github.com/google/uuidd", UUID, 0.15);
  assert.equal(hit?.signal, "repository-typo");
  assert.equal(hit?.distance, 1);
});

// Neither component matches exactly, so only the whole path shows the
// resemblance. Without this comparison the doubled typo walks straight past.
test("a typo in BOTH the owner and the repository is still caught", () => {
  const hit = compareToProtected("github.com/gooogle/uuidd", UUID, 0.15);
  assert.equal(hit?.signal, "module-typo");
  assert.equal(hit?.distance, 2);

  assert.equal(
    compareToProtected("github.com/gooogle/uuidd", UUID, 0.08),
    undefined,
    "standard's narrower net does not reach two edits across the whole path",
  );
});

test("a near-miss on a protected owner is caught even for an unknown repository", () => {
  const hit = compareToProtectedOwners(
    "github.com/kubernetess/some-tool",
    ["google", "kubernetes", "hashicorp"],
    0.15,
  );
  assert.equal(hit?.signal, "protected-owner-typo");
  assert.equal(hit?.protectedIdentity, "kubernetes");
});

// NEGATIVE CORPUS. Every one of these is an ordinary dependency; a check that
// flags them gets turned off, and a check that is off protects nobody.
test("real, unrelated modules are not flagged", () => {
  const corpus = [
    { module: "github.com/google/uuid" },
    { module: "github.com/stretchr/testify" },
    { module: "golang.org/x/sync" },
    { module: "github.com/spf13/cobra" },
  ];

  for (const candidate of [
    "github.com/google/uuid", // the real thing
    "github.com/google/uuid/v2", // a major version of the real thing
    "github.com/prometheus/client_golang",
    "github.com/go-chi/chi",
    "golang.org/x/text",
    "github.com/spf13/viper", // same owner, unrelated repository
    "github.com/stretchr/objx", // same owner, unrelated repository
    "gopkg.in/yaml.v3",
    "github.com/mattn/go-sqlite3",
  ]) {
    for (const known of corpus) {
      const hit = compareToProtected(candidate, known, 0.25);
      assert.equal(hit, undefined, `${candidate} vs ${known.module}: ${hit?.message ?? ""}`);
    }
  }
});

// Go module paths are case-sensitive, and the proxy escapes capitals precisely
// because `Google/uuid` and `google/uuid` are different modules.
test("a module differing from a protected one only in case is still an impersonation", () => {
  const hit = compareToProtected("github.com/Google/uuid", UUID, 0.08);
  assert.notEqual(hit, undefined);
  assert.equal(compareToProtected("github.com/google/uuid", UUID, 0.08), undefined, "the real one");
  assert.equal(
    compareToProtected("github.com/google/uuid/v2", UUID, 0.08),
    undefined,
    "a major version of the real one",
  );
});

test("an owner that is genuinely different is not an owner typo", () => {
  assert.equal(
    compareToProtectedOwners("github.com/mattn/go-sqlite3", ["google", "kubernetes"], 0.25),
    undefined,
  );
});

// ---------------------------------------------------------------------------
// The corpus is not an allow-list (SPEC 12.1, 12.6)
// ---------------------------------------------------------------------------

test("a corpus document is read per ecosystem, in both entry forms", () => {
  const parsed = parseTrustDocument({
    version: 1,
    protected: {
      go: {
        modules: [
          { module: "github.com/google/uuid", repository: "github.com/google/uuid" },
          "golang.org/x/sync",
        ],
        owners: ["google", "golang"],
      },
    },
  });

  assert.deepEqual(parsed.ecosystems["go"]?.modules.map((m) => m.module), [
    "github.com/google/uuid",
    "golang.org/x/sync",
  ]);
  assert.deepEqual(parsed.ecosystems["go"]?.owners, ["google", "golang"]);
});

test("malformed corpus entries are dropped with a warning, never guessed", () => {
  const parsed = parseTrustDocument({
    protected: {
      go: { modules: [{ notAModule: true }, 42, ""], owners: [{}, ""] },
      npm: "not a mapping",
    },
  });
  assert.equal(parsed.ecosystems["go"], undefined, "nothing readable, nothing loaded");
  assert.ok(parsed.warnings.length >= 3, parsed.warnings.join("; "));
});

test("global and project corpora add together", async () => {
  const dir = await mkdtemp(join(tmpdir(), "supplyguard-trust-"));
  tempRoots.push(dir);
  await writeFile(
    join(dir, "global.yaml"),
    "version: 1\nprotected:\n  go:\n    owners: [google]\n",
  );
  await writeFile(
    join(dir, "project.yaml"),
    "version: 1\nprotected:\n  go:\n    modules:\n      - github.com/mycorp/lib\n    owners: [google, mycorp]\n",
  );

  const corpus = await loadTrustCorpus([join(dir, "global.yaml"), join(dir, "project.yaml")]);
  assert.equal(corpus.empty, false);
  assert.deepEqual(corpus.ecosystems["go"]?.owners, ["google", "mycorp"], "merged, de-duplicated");
  assert.equal(countIdentities(corpus), 3);
  assert.equal(corpus.sources.length, 2);
});

test("a missing corpus is not an error and analysis simply does not run", async () => {
  const corpus = await loadTrustCorpus(["/nonexistent/global.yaml", "/nonexistent/project.yaml"]);
  assert.deepEqual(corpus.ecosystems, {});
  assert.equal(corpus.empty, true);
  assert.deepEqual(corpus.warnings, []);
  assert.equal(EMPTY_CORPUS.empty, true);
});

// ---------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------

async function repoWithCorpus(
  profile: string,
  corpus: string | undefined,
): Promise<{ call: (c: string) => Promise<{ block?: boolean; reason?: string } | undefined>; prompts: string[]; notices: string[] }> {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-id-repo-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-id-home-"));
  tempRoots.push(repo, home);
  await writeFile(join(repo, ".supplyguard.yaml"), `version: 1\nprofile: ${profile}\n`);
  await writeFile(join(repo, "go.mod"), "module m\n\ngo 1.22\n");
  // Paranoid denies a dependency mutation in a project with no vendor tree
  // (SPEC 9.3); these tests are about identity, so the fixture is vendored.
  await mkdir(join(repo, "vendor"), { recursive: true });
  await writeFile(join(repo, "vendor", "modules.txt"), "");
  if (corpus !== undefined) await writeFile(join(repo, ".supplyguard-trust.yaml"), corpus);

  const prompts: string[] = [];
  const notices: string[] = [];
  const runtime = createRuntime({ home, env: {}, proxy: { env: { GOPROXY: "off" } } });
  const ctx = {
    cwd: repo,
    hasUI: true,
    mode: "tui" as const,
    ui: {
      select: async (title: string) => {
        prompts.push(title);
        return title.includes("override this denial") ? "Keep the denial" : "Approve once";
      },
      confirm: async () => false,
      input: async () => undefined,
      notify: (message: string) => {
        notices.push(message);
      },
    },
    sessionManager: { getSessionId: () => "session-1" },
  };

  return {
    prompts,
    notices,
    call: async (command: string) => {
      const module = /go get ([^@\s]+)@(\S+)/.exec(command);
      if (module !== null) {
        await runtime.justifyTool(
          {
            module: module[1],
            version: module[2],
            purpose: "test",
            stdlibConsidered: true,
            stdlibInsufficientReason: "none",
          },
          ctx as never,
        );
      }
      return runtime.onToolCall(
        { toolName: "bash", toolCallId: "1", input: { command } },
        ctx as never,
      );
    },
  };
}

const CORPUS = `version: 1
protected:
  go:
    modules:
      - module: github.com/google/uuid
    owners:
      - google
`;

test("a repository squat is denied in hardened and asked about in standard", async () => {
  const hardened = await repoWithCorpus("hardened", CORPUS);
  const blocked = await hardened.call("go get github.com/random-owner/uuid@v1.0.0");
  assert.equal(blocked?.block, true);
  assert.match(hardened.prompts.join("\n"), /repository-squatting attack/);

  const standard = await repoWithCorpus("standard", CORPUS);
  assert.equal(
    await standard.call("go get github.com/random-owner/uuid@v1.0.0"),
    undefined,
    "standard asks, and this human approved",
  );
});

// NEGATIVE: the corpus protects identities; it does not gate everything else.
test("a module unrelated to the corpus is unaffected", async () => {
  const h = await repoWithCorpus("hardened", CORPUS);
  assert.equal(await h.call("go get github.com/spf13/cobra@v1.8.0"), undefined);
});

test("the real protected module is not flagged as a squat of itself", async () => {
  const h = await repoWithCorpus("paranoid", CORPUS);
  assert.equal(await h.call("go get github.com/google/uuid@v1.6.0"), undefined);
});

// SPEC 12.6: absence of a corpus never denies, but paranoid must say so.
test("with no corpus, analysis is off and paranoid says so", async () => {
  const h = await repoWithCorpus("paranoid", undefined);
  assert.equal(
    await h.call("go get github.com/random-owner/uuid@v1.0.0"),
    undefined,
    "a missing corpus alone must not block a dependency operation",
  );
  assert.match(h.prompts.join("\n"), /analysis is DISABLED/);
});
