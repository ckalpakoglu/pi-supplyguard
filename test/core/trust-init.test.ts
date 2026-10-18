/**
 * `/supplyguard-trust init` (M14): the corpus tool. The flagship identity
 * analysis is dormant without a corpus (KNOWN-GAPS 1.4); this makes seeding
 * one a single command from the repository's own manifest.
 */
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRuntime, type SupplyGuardRuntime } from "../../src/index.ts";

const tempRoots: string[] = [];

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

const GO_MOD = [
  "module example.com/app",
  "",
  "go 1.22",
  "",
  "require (",
  "  github.com/google/uuid v1.6.0",
  "  golang.org/x/mod v0.17.0",
  ")",
  "",
].join("\n");

function contextFor(repo: string, prompts: string[]) {
  return {
    cwd: repo,
    hasUI: true,
    mode: "tui" as const,
    ui: {
      select: async (title: string) => {
        prompts.push(title);
        return "Deny";
      },
      confirm: async () => false,
      input: async () => "a reason",
      notify: () => {},
    },
    sessionManager: { getSessionId: () => "session-1" },
  };
}

test("init seeds the corpus from go.mod", async () => {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-trust-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-trust-home-"));
  tempRoots.push(repo, home);
  await writeFile(join(repo, "go.mod"), GO_MOD);

  // GOPROXY/OSV off: nothing in the suite reaches the network.
  const runtime = createRuntime({ home, env: {}, proxy: { env: { GOPROXY: "off" } }, osv: { env: { GOPROXY: "off" } } });
  await runtime.trustCommand("init", contextFor(repo, []) as never);

  const corpus = await readFile(join(repo, ".supplyguard-trust.yaml"), "utf8");
  assert.match(corpus, /^version: 1/);
  assert.match(corpus, /protected:/);
  assert.ok(corpus.includes("- github.com/google/uuid"));
  assert.ok(corpus.includes("- golang.org/x/mod"));
});

test("init never overwrites an existing corpus", async () => {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-trust-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-trust-home-"));
  tempRoots.push(repo, home);
  await writeFile(join(repo, "go.mod"), GO_MOD);
  await writeFile(join(repo, ".supplyguard-trust.yaml"), "version: 1\nprotected: {}\n");

  // GOPROXY/OSV off: nothing in the suite reaches the network.
  const runtime = createRuntime({ home, env: {}, proxy: { env: { GOPROXY: "off" } }, osv: { env: { GOPROXY: "off" } } });
  await runtime.trustCommand("init", contextFor(repo, []) as never);

  const corpus = await readFile(join(repo, ".supplyguard-trust.yaml"), "utf8");
  assert.equal(corpus, "version: 1\nprotected: {}\n");
});

test("the seeded corpus actually arms the identity analysis", async () => {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-trust-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-trust-home-"));
  tempRoots.push(repo, home);
  await writeFile(join(repo, "go.mod"), GO_MOD);

  const seeder: SupplyGuardRuntime = createRuntime({
    home,
    env: {},
    proxy: { env: { GOPROXY: "off" } },
    osv: { env: { GOPROXY: "off" } },
  });
  await seeder.trustCommand("init", contextFor(repo, []) as never);

  // A fresh runtime so the corpus is loaded from disk, not held over from
  // before init ran.
  const prompts: string[] = [];
  const second: SupplyGuardRuntime = createRuntime({
    home,
    env: {},
    proxy: { env: { GOPROXY: "off" } },
    osv: { env: { GOPROXY: "off" } },
  });
  const ctx = contextFor(repo, prompts);

  await second.justifyTool(
    {
      module: "github.com/google/uu1d",
      version: "v1.6.0",
      purpose: "corpus smoke",
      stdlibConsidered: true,
      stdlibInsufficientReason: "none",
    },
    ctx as never,
  );
  await second.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "go get github.com/google/uu1d@v1.6.0" } },
    ctx as never,
  );
  assert.match(
    prompts.join("\n\n"),
    /uuid|protected/i,
    "the seeded corpus is live: the typo of a seeded module is flagged",
  );
});
