/**
 * Release cooldown and scoped one-shot overrides (SPEC 11.1, 17.2, 23.1).
 *
 * Two things are load-bearing here. A version published an hour ago is treated
 * as a risk in its own right, per profile. And the override that lifts that
 * denial is the ONLY path in the codebase from `deny` to `allow` -- so most of
 * these tests are about what it refuses to lift.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { createRuntime } from "../../src/index.ts";

const ageTempRoots: string[] = [];

after(async () => {
  await Promise.all(ageTempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

import {
  applyHumanOverride,
  evaluateLocal,
  isOverridable,
  localFinding,
} from "../../src/core/decisions.ts";
import { assessReleaseAge, type ReleaseLookup } from "../../src/core/release-age.ts";
import {
  escapeModulePath,
  isPrivateModule,
  lookupReleaseDate,
  matchesPattern,
  resolveProxyBase,
  type FetchLike,
} from "../../src/adapters/go/proxy.ts";

const NOW = new Date("2026-09-02T00:00:00.000Z");

function daysAgo(days: number): ReleaseLookup {
  return { kind: "known", publishedAt: new Date(NOW.getTime() - days * 86_400_000) };
}

function assess(lookup: ReleaseLookup, profile: "standard" | "hardened" | "paranoid") {
  return assessReleaseAge(lookup, {
    profile,
    minimumDays: 10,
    now: NOW,
    artifact: "github.com/foo/bar",
    version: "v1.7.2",
  });
}

// ---------------------------------------------------------------------------
// SPEC 11.1: standard warns, hardened denies, paranoid denies with a reason
// ---------------------------------------------------------------------------

test("an artifact older than the cooldown passes in every profile", () => {
  for (const profile of ["standard", "hardened", "paranoid"] as const) {
    assert.equal(assess(daysAgo(94), profile)?.decision, "allow", profile);
  }
});

test("a fresh artifact warns in standard and denies in hardened and paranoid", () => {
  const standard = assess(daysAgo(1), "standard");
  assert.equal(standard?.decision, "warn");
  assert.equal(standard?.overridable, false, "nothing to override: it still asks");

  const hardened = assess(daysAgo(1), "hardened");
  assert.equal(hardened?.decision, "deny");
  assert.equal(hardened?.overridable, true, "SPEC 11.1: explicit one-shot override");
  assert.equal(hardened?.reasonRequired, false);

  const paranoid = assess(daysAgo(1), "paranoid");
  assert.equal(paranoid?.decision, "deny");
  assert.equal(paranoid?.overridable, true);
  assert.equal(paranoid?.reasonRequired, true, "SPEC 11.1: reason-required exceptional override");
});

test("the boundary is inclusive: exactly the minimum age is old enough", () => {
  assert.equal(assess(daysAgo(10), "paranoid")?.decision, "allow");
  assert.equal(assess(daysAgo(9.9), "hardened")?.decision, "deny");
});

// SECURITY: unknown is never silently clean in paranoid (SPEC 16).
test("an unavailable release date warns below paranoid and fails closed in paranoid", () => {
  const unavailable: ReleaseLookup = { kind: "unavailable", reason: "the proxy did not answer in time" };

  assert.equal(assess(unavailable, "standard")?.decision, "warn");
  assert.equal(assess(unavailable, "hardened")?.decision, "warn");

  const paranoid = assess(unavailable, "paranoid");
  assert.equal(paranoid?.decision, "deny");
  assert.equal(
    paranoid?.overridable,
    false,
    "SPEC 17.3: an outage must not become a recurring one-shot bypass",
  );
});

// A private module is deliberately never queried, and that silence must not
// read as a provider failure -- paranoid could otherwise never take an
// internal dependency.
test("a module that was deliberately not looked up produces no finding", () => {
  const notApplicable: ReleaseLookup = { kind: "not-applicable", reason: "GOPRIVATE" };
  for (const profile of ["standard", "hardened", "paranoid"] as const) {
    assert.equal(assess(notApplicable, profile), undefined, profile);
  }
});

// ---------------------------------------------------------------------------
// The override: the only deny -> allow path there is
// ---------------------------------------------------------------------------

const AT = "2026-09-02T00:00:00.000Z";

function denial(overridable: boolean) {
  return evaluateLocal([
    localFinding("release-age", "release-age", "deny", "too new", { overridable }),
  ]);
}

test("only a denial whose every decisive finding opted in can be overridden", () => {
  assert.equal(isOverridable(denial(true)), true);
  assert.equal(isOverridable(denial(false)), false);

  // One invariant beside a waivable finding makes the whole denial final.
  const mixed = evaluateLocal([
    localFinding("release-age", "release-age", "deny", "too new", { overridable: true }),
    localFinding("go", "event:ChecksumBypass", "deny", "GOSUMDB=off"),
  ]);
  assert.equal(isOverridable(mixed), false);

  assert.equal(isOverridable(evaluateLocal([])), false, "nothing to override");
  assert.equal(
    isOverridable(evaluateLocal([localFinding("x", "y", "ask", "asks")])),
    false,
    "an ask is not an override candidate",
  );
});

test("a granted override lowers the denial once and records the reason", () => {
  const result = applyHumanOverride(denial(true), {
    verifiedBy: "human-ui",
    granted: true,
    at: AT,
    reason: "hotfix for CVE triage, reviewed by the security team",
  });

  assert.equal(result.decision, "allow");
  assert.match(result.findings.at(-1)?.message ?? "", /Overridden once by a human/);
  assert.match(result.findings.at(-1)?.message ?? "", /hotfix for CVE triage/);
});

// SECURITY: the guard lives in the combinator, not at the call site.
test("an override cannot lift a denial that did not opt in, even if granted", () => {
  const result = applyHumanOverride(denial(false), {
    verifiedBy: "human-ui",
    granted: true,
    at: AT,
    reason: "please",
  });

  assert.equal(result.decision, "deny", "an invariant is not waivable by any answer");
  assert.match(result.findings.at(-1)?.message ?? "", /not waivable/);
});

test("declining an override leaves the denial exactly where it was", () => {
  const result = applyHumanOverride(denial(true), {
    verifiedBy: "human-ui",
    granted: false,
    at: AT,
  });
  assert.equal(result.decision, "deny");
  assert.match(result.findings.at(-1)?.message ?? "", /No override was granted/);
});

// ---------------------------------------------------------------------------
// The proxy: privacy first
// ---------------------------------------------------------------------------

test("module paths are escaped the way the proxy protocol requires", () => {
  assert.equal(escapeModulePath("github.com/foo/bar"), "github.com/foo/bar");
  assert.equal(
    escapeModulePath("github.com/BurntSushi/toml"),
    "github.com/!burnt!sushi/toml",
    "an unescaped capital 404s and looks like an outage",
  );
});

test("GOPRIVATE patterns match per path element, and prefixes count", () => {
  assert.equal(matchesPattern("github.com/mycorp/*", "github.com/mycorp/lib"), true);
  assert.equal(matchesPattern("github.com/mycorp/*", "github.com/mycorp/lib/v2"), true);
  assert.equal(matchesPattern("github.com/mycorp/*", "github.com/other/lib"), false);
  assert.equal(matchesPattern("*.corp.example", "internal.corp.example/lib"), true);
  assert.equal(matchesPattern("github.com/mycorp", "github.com/mycorp/lib"), true);
  assert.equal(matchesPattern("github.com/mycorp/lib", "github.com/mycorp"), false);
  // `*` must not cross a separator.
  assert.equal(matchesPattern("github.com/*", "github.com/a/b"), true);
  assert.equal(matchesPattern("github.com/*/x", "github.com/a/b/x"), false);
});

// SECURITY: the whole point of GOPRIVATE is that the name never leaves.
test("a private module is never sent to a proxy", async () => {
  const env = { GOPRIVATE: "github.com/mycorp/*,*.internal.example" };
  assert.equal(isPrivateModule("github.com/mycorp/secret", env), true);
  assert.equal(isPrivateModule("host.internal.example/lib", env), true);
  assert.equal(isPrivateModule("github.com/public/lib", env), false);

  const lookup = await lookupReleaseDate("github.com/mycorp/secret", "v1.0.0", {
    env,
    fetch: () => {
      throw new Error("a private module reached the network");
    },
  });
  assert.equal(lookup.kind, "not-applicable");
});

test("GONOPROXY also keeps a module off the proxy", async () => {
  assert.equal(isPrivateModule("git.example/lib", { GONOPROXY: "git.example/*" }), true);
});

test("GOPROXY selects the proxy, and off or direct means no lookup", () => {
  assert.equal(resolveProxyBase({}), "https://proxy.golang.org");
  assert.equal(resolveProxyBase({ GOPROXY: "" }), "https://proxy.golang.org");
  assert.equal(resolveProxyBase({ GOPROXY: "https://corp.example/mod" }), "https://corp.example/mod");
  assert.equal(resolveProxyBase({ GOPROXY: "https://corp.example/mod/" }), "https://corp.example/mod");
  assert.equal(resolveProxyBase({ GOPROXY: "https://a.example,direct" }), "https://a.example");
  assert.equal(resolveProxyBase({ GOPROXY: "off" }), undefined);
  assert.equal(resolveProxyBase({ GOPROXY: "direct" }), undefined);
});

test("GOPROXY=off performs no lookup at all", async () => {
  const lookup = await lookupReleaseDate("github.com/foo/bar", "v1.0.0", {
    env: { GOPROXY: "off" },
    fetch: () => {
      throw new Error("GOPROXY=off still reached the network");
    },
  });
  assert.equal(lookup.kind, "not-applicable");
});

function fakeFetch(body: string, ok = true, status = 200): FetchLike {
  return async () => ({ ok, status, text: async () => body });
}

test("a well-formed proxy answer yields the publication date", async () => {
  const seen: string[] = [];
  const lookup = await lookupReleaseDate("github.com/BurntSushi/toml", "v1.7.2", {
    env: {},
    fetch: async (url) => {
      seen.push(url);
      return { ok: true, status: 200, text: async () => '{"Version":"v1.7.2","Time":"2026-05-01T10:00:00Z"}' };
    },
  });

  assert.deepEqual(seen, [
    "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.7.2.info",
  ]);
  assert.equal(lookup.kind, "known");
  if (lookup.kind === "known") {
    assert.equal(lookup.publishedAt.toISOString(), "2026-05-01T10:00:00.000Z");
  }
});

test("every proxy failure mode becomes an unavailable answer, never a throw", async () => {
  for (const [label, options] of [
    ["HTTP 404", { fetch: fakeFetch("not found", false, 404) }],
    ["not JSON", { fetch: fakeFetch("<html>") }],
    ["JSON but not an object", { fetch: fakeFetch('"nope"') }],
    ["no Time field", { fetch: fakeFetch('{"Version":"v1.0.0"}') }],
    ["unreadable Time", { fetch: fakeFetch('{"Time":"soon"}') }],
    ["oversized document", { fetch: fakeFetch(`{"Time":"${"x".repeat(100_000)}"}`) }],
    [
      "a thrown request",
      {
        fetch: () => {
          throw new Error("ECONNREFUSED");
        },
      },
    ],
  ] as const) {
    const lookup = await lookupReleaseDate("github.com/foo/bar", "v1.0.0", {
      env: {},
      ...options,
    });
    assert.equal(lookup.kind, "unavailable", label);
  }
});

test("a proxy that never answers is abandoned rather than hanging the gate", async () => {
  const lookup = await lookupReleaseDate("github.com/foo/bar", "v1.0.0", {
    env: {},
    timeoutMs: 10,
    fetch: (_url, init) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => {
          const error = new Error("aborted");
          error.name = "AbortError";
          reject(error);
        });
      }),
  });
  assert.equal(lookup.kind, "unavailable");
  if (lookup.kind === "unavailable") assert.match(lookup.reason, /did not answer in time/);
});

// ---------------------------------------------------------------------------
// End to end: cooldown and override through the real runtime
// ---------------------------------------------------------------------------

const FRESH = '{"Version":"v1.7.2","Time":"2026-09-01T00:00:00Z"}';
const OLD = '{"Version":"v1.7.2","Time":"2026-01-01T00:00:00Z"}';

interface Answers {
  readonly prompts: string[];
  readonly inputs: string[];
  select: string | undefined;
  input: string | undefined;
}

async function runtimeWith(
  profile: "standard" | "hardened" | "paranoid",
  body: string,
  answers: Partial<Answers> = {},
): Promise<{ run: () => Promise<{ block?: boolean; reason?: string } | undefined>; seen: Answers; home: string }> {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-age-repo-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-age-home-"));
  ageTempRoots.push(repo, home);
  await writeFile(join(repo, ".supplyguard.yaml"), `version: 1\nprofile: ${profile}\n`);
  await writeFile(join(repo, "go.mod"), "module m\n\ngo 1.22\n");
  // Paranoid denies a dependency mutation in a project with no vendor tree
  // (SPEC 9.3), and that denial is an invariant rather than a judgement call.
  // These tests are about the COOLDOWN, so the repository is vendored and
  // consistent; "an override is never offered for an invariant" is covered
  // separately below.
  await mkdir(join(repo, "vendor"), { recursive: true });
  await writeFile(join(repo, "vendor", "modules.txt"), "");

  const seen: Answers = {
    prompts: [],
    inputs: [],
    select: answers.select ?? "Approve once",
    input: answers.input,
  };
  const ctx = {
    cwd: repo,
    hasUI: true,
    mode: "tui" as const,
    ui: {
      select: async (title: string, options: readonly string[]) => {
        seen.prompts.push(title);
        // The override prompt offers different options from the approval one.
        if (options.includes("Override once")) {
          return answers.select === "Override once" ? "Override once" : "Keep the denial";
        }
        return seen.select;
      },
      confirm: async () => false,
      input: async (title: string) => {
        seen.inputs.push(title);
        return seen.input;
      },
      notify: () => {},
    },
    sessionManager: { getSessionId: () => "session-1" },
  };

  const runtime = createRuntime({
    home,
    env: {},
    now: () => new Date("2026-09-02T00:00:00.000Z"),
    proxy: { env: {}, fetch: async () => ({ ok: true, status: 200, text: async () => body }) },
    // These tests are about the cooldown; OSV is covered separately and no
    // test may reach the network.
    osv: { env: { GOPROXY: "off" } },
  });

  return {
    seen,
    home,
    run: async () => {
      await runtime.justifyTool(
        {
          module: "github.com/foo/bar",
          version: "v1.7.2",
          purpose: "needed for the feature under test",
          stdlibConsidered: true,
          stdlibInsufficientReason: "no stdlib equivalent",
        },
        ctx as never,
      );
      return runtime.onToolCall(
        {
          toolName: "bash",
          toolCallId: "1",
          input: { command: "go get github.com/foo/bar@v1.7.2" },
        },
        ctx as never,
      );
    },
  };
}

test("an artifact past the cooldown is approved normally", async () => {
  const h = await runtimeWith("hardened", OLD);
  assert.equal(await h.run(), undefined);
  assert.equal(h.seen.inputs.length, 0, "no reason is asked for when nothing was denied");
});

test("standard warns about a fresh artifact but still lets a human approve it", async () => {
  const h = await runtimeWith("standard", FRESH);
  assert.equal(await h.run(), undefined);
  assert.match(h.seen.prompts.join("\n"), /inside the 10-day release cooldown/);
});

test("hardened denies a fresh artifact and offers a one-shot override", async () => {
  const declined = await runtimeWith("hardened", FRESH);
  const blocked = await declined.run();
  assert.equal(blocked?.block, true);
  assert.match(declined.seen.prompts.join("\n"), /override this denial once/);
  assert.equal(declined.seen.inputs.length, 0, "hardened does not demand a written reason");

  const overridden = await runtimeWith("hardened", FRESH, { select: "Override once" });
  assert.equal(await overridden.run(), undefined, "the human waived it once");
});

// SPEC 11.1: a paranoid exceptional override without a stated reason is not an
// exception, it is a habit.
test("paranoid demands a written reason before waiving the cooldown", async () => {
  const noReason = await runtimeWith("paranoid", FRESH, {
    select: "Override once",
    input: "   ",
  });
  const blocked = await noReason.run();
  assert.equal(blocked?.block, true, "an empty reason is not a reason");
  assert.equal(noReason.seen.inputs.length, 1);

  const withReason = await runtimeWith("paranoid", FRESH, {
    select: "Override once",
    input: "security team reviewed the diff; needed for the incident fix",
  });
  assert.equal(await withReason.run(), undefined);

  const log = await readFile(
    join(withReason.home, ".local", "state", "pi-supplyguard", "audit.jsonl"),
    "utf8",
  );
  assert.match(log, /security team reviewed the diff/, "the reason is durable evidence");
});

// SECURITY: an invariant is not a judgement call, so no prompt can lift it.
test("an override is never offered for a floating version or a checksum bypass", async () => {
  for (const command of ["go get github.com/foo/bar@latest", "GOSUMDB=off go build ./..."]) {
    const repo = await mkdtemp(join(tmpdir(), "supplyguard-inv-repo-"));
    const home = await mkdtemp(join(tmpdir(), "supplyguard-inv-home-"));
    ageTempRoots.push(repo, home);
    const prompts: string[] = [];
    const runtime = createRuntime({ home, env: {}, proxy: { env: { GOPROXY: "off" } } });
    const ctx = {
      cwd: repo,
      hasUI: true,
      mode: "tui" as const,
      ui: {
        select: async (title: string) => {
          prompts.push(title);
          return "Override once";
        },
        confirm: async () => false,
        input: async () => "because I say so",
        notify: () => {},
      },
      sessionManager: { getSessionId: () => "session-1" },
    };

    const result = await runtime.onToolCall(
      { toolName: "bash", toolCallId: "1", input: { command } },
      ctx as never,
    );
    assert.equal(result?.block, true, command);
    assert.equal(
      prompts.some((p) => p.includes("override this denial once")),
      false,
      `no override may be offered for: ${command}`,
    );
  }
});
