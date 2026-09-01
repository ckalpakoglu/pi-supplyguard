/**
 * The Pi wiring layer, `createRuntime` (SPEC 8.2, 19).
 *
 * `src/index.ts` is where policy meets the host, so its own failure modes are
 * security-relevant: a crash here must not become a silent bypass, and
 * `/supplyguard-profile` must be incapable of lowering the effective profile
 * or of persisting anything.
 */
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { createAdapterRegistry, type EcosystemAdapter } from "../../src/adapters/registry.ts";
import type { SupplyChainEvent } from "../../src/core/events.ts";
import { createRuntime, type SupplyGuardRuntime } from "../../src/index.ts";

const tempRoots: string[] = [];

async function tempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  tempRoots.push(dir);
  return dir;
}

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

interface Recorder {
  readonly notices: string[];
  readonly prompts: string[];
  answer: string | undefined;
}

/** A fake `ExtensionContext`. `sessionId` may be made to throw. */
function context(
  cwd: string,
  recorder: Recorder,
  options: { hasUI?: boolean; sessionThrows?: boolean } = {},
) {
  return {
    cwd,
    hasUI: options.hasUI ?? true,
    mode: (options.hasUI ?? true) ? ("tui" as const) : ("print" as const),
    ui: {
      select: async (title: string) => {
        recorder.prompts.push(title);
        return recorder.answer;
      },
      confirm: async () => false,
      input: async () => undefined,
      notify: (message: string) => {
        recorder.notices.push(message);
      },
    },
    sessionManager: {
      getSessionId: () => {
        if (options.sessionThrows === true) throw new Error("session unavailable");
        return "session-1";
      },
    },
  };
}

function recorder(answer: string | undefined = undefined): Recorder {
  return { notices: [], prompts: [], answer };
}

/** A runtime rooted at an isolated HOME and repo, with a controllable clock. */
async function runtimeAt(
  repo: string,
  options: { clock?: { value: Date }; adapters?: readonly EcosystemAdapter[] } = {},
): Promise<{ runtime: SupplyGuardRuntime; home: string }> {
  const home = await tempDir("supplyguard-home-");
  const clock = options.clock ?? { value: new Date("2026-09-01T00:00:00.000Z") };
  const runtime = createRuntime({
    home,
    env: {},
    now: () => clock.value,
    registry: createAdapterRegistry(options.adapters ?? []),
  });
  return { runtime, home };
}

function mutationAdapter(): EcosystemAdapter {
  const event: SupplyChainEvent = {
    eventClass: "DependencyAdd",
    ecosystem: "test",
    classification: "THIRD_PARTY_MUTATION",
    artifact: "example.com/pkg",
    version: "v1.0.0",
    summary: "adds a dependency",
  };
  return {
    id: "test",
    inspectToolCall: () => ({ classification: "THIRD_PARTY_MUTATION", events: [event] }),
  };
}

const CALL = { toolName: "bash", input: { command: "ls" } };

// ---------------------------------------------------------------------------
// Finding 1: the wiring layer must fail closed, exactly like the engine.
// ---------------------------------------------------------------------------

test("a failure in the wiring layer blocks the call instead of passing it through", async () => {
  const repo = await tempDir("supplyguard-repo-");
  const { runtime } = await runtimeAt(repo);
  const rec = recorder();

  const result = await runtime.onToolCall(
    CALL,
    context(repo, rec, { sessionThrows: true }) as never,
  );

  assert.equal(result?.block, true, "an internal failure must not become ALLOW");
  assert.match(result?.reason ?? "", /failing closed/);
  assert.equal(rec.notices.length, 1, "the operator is told, not just the agent");
  assert.match(rec.notices[0] ?? "", /failing closed/);
});

// ---------------------------------------------------------------------------
// Baseline behavior: SupplyGuard must not tax ordinary development.
// ---------------------------------------------------------------------------

test("with no adapters registered every tool call proceeds untouched", async () => {
  const repo = await tempDir("supplyguard-repo-");
  const { runtime } = await runtimeAt(repo);
  const rec = recorder();

  const result = await runtime.onToolCall(CALL, context(repo, rec) as never);

  assert.equal(result, undefined, "undefined means 'no opinion, proceed'");
  assert.deepEqual(rec.prompts, []);
});

test("a headless session is not prompted and the gated call is blocked", async () => {
  const repo = await tempDir("supplyguard-repo-");
  const { runtime } = await runtimeAt(repo, { adapters: [mutationAdapter()] });
  const rec = recorder();

  const result = await runtime.onToolCall(
    CALL,
    context(repo, rec, { hasUI: false }) as never,
  );

  assert.equal(result?.block, true);
  assert.deepEqual(rec.prompts, [], "no human is reachable, so none is asked");
});

// ---------------------------------------------------------------------------
// Finding 2 / invariant 8: /supplyguard-profile may tighten, never weaken,
// and never persists.
// ---------------------------------------------------------------------------

test("the profile command tightens the effective profile for this session only", async () => {
  const repo = await tempDir("supplyguard-repo-");
  const { runtime, home } = await runtimeAt(repo);
  const rec = recorder();

  assert.equal(runtime.sessionProfileFloor(), undefined);

  await runtime.profileCommand("paranoid", context(repo, rec) as never);
  assert.equal(runtime.sessionProfileFloor(), "paranoid");
  assert.match(rec.notices.at(-1) ?? "", /tightened to paranoid/);

  // Nothing was written back into the repository or the global config.
  await assert.rejects(readFile(join(repo, ".supplyguard.yaml"), "utf8"));
  await assert.rejects(
    readFile(join(home, ".config", "pi-supplyguard", "config.yaml"), "utf8"),
  );
});

// SECURITY INVARIANT: a chat command can never lower enforcement.
test("the profile command refuses to lower the effective profile", async () => {
  const repo = await tempDir("supplyguard-repo-");
  const { runtime } = await runtimeAt(repo);
  const rec = recorder();

  await runtime.profileCommand("paranoid", context(repo, rec) as never);
  assert.equal(runtime.sessionProfileFloor(), "paranoid");

  for (const weaker of ["standard", "hardened"]) {
    await runtime.profileCommand(weaker, context(repo, rec) as never);
    assert.equal(
      runtime.sessionProfileFloor(),
      "paranoid",
      `"${weaker}" must not lower the session floor`,
    );
    assert.match(rec.notices.at(-1) ?? "", /profile stays paranoid/);
  }
});

test("the profile command rejects an unknown profile rather than guessing", async () => {
  const repo = await tempDir("supplyguard-repo-");
  const { runtime } = await runtimeAt(repo);
  const rec = recorder();

  await runtime.profileCommand("ultra", context(repo, rec) as never);

  assert.equal(runtime.sessionProfileFloor(), undefined);
  assert.match(rec.notices.at(-1) ?? "", /unknown profile "ultra"/);
});

test("the profile command with no argument reports without changing anything", async () => {
  const repo = await tempDir("supplyguard-repo-");
  const { runtime } = await runtimeAt(repo);
  const rec = recorder();

  await runtime.profileCommand("", context(repo, rec) as never);

  assert.equal(runtime.sessionProfileFloor(), undefined);
  assert.match(rec.notices.at(-1) ?? "", /SupplyGuard profile: standard/);
});

// ---------------------------------------------------------------------------
// Finding 3: configuration is re-read, with bounded staleness.
// ---------------------------------------------------------------------------

test("a project configuration added mid-session is picked up once the cache expires", async () => {
  const repo = await tempDir("supplyguard-repo-");
  const clock = { value: new Date("2026-09-01T00:00:00.000Z") };
  const { runtime } = await runtimeAt(repo, { clock });
  const rec = recorder();

  await runtime.statusCommand("", context(repo, rec) as never);
  assert.match(rec.notices.at(-1) ?? "", /Effective profile {4}standard/);

  await writeFile(join(repo, ".supplyguard.yaml"), "version: 1\nprofile: paranoid\n");

  // Still cached: the previous load is only a moment old.
  await runtime.statusCommand("", context(repo, rec) as never);
  assert.match(rec.notices.at(-1) ?? "", /Effective profile {4}standard/);

  // Past the TTL, the tightening takes effect without restarting Pi.
  clock.value = new Date("2026-09-01T00:00:10.000Z");
  await runtime.statusCommand("", context(repo, rec) as never);
  assert.match(rec.notices.at(-1) ?? "", /Effective profile {4}paranoid/);
});

// SECURITY INVARIANT: a project may tighten the global baseline, never weaken it.
test("a project configuration cannot weaken the global profile", async () => {
  const repo = await tempDir("supplyguard-repo-");
  const home = await tempDir("supplyguard-home-");
  const globalDir = join(home, ".config", "pi-supplyguard");
  await mkdtempGlobal(globalDir);
  await writeFile(join(globalDir, "config.yaml"), "version: 1\nprofile: hardened\n");
  await writeFile(join(repo, ".supplyguard.yaml"), "version: 1\nprofile: standard\n");

  const runtime = createRuntime({ home, env: {}, registry: createAdapterRegistry() });
  const rec = recorder();
  await runtime.statusCommand("", context(repo, rec) as never);

  const output = rec.notices.at(-1) ?? "";
  assert.match(output, /Effective profile {4}hardened/);
  assert.match(output, /weaker than the established baseline/);
});

/** `mkdir -p` without importing another symbol into the test's top scope. */
async function mkdtempGlobal(dir: string): Promise<void> {
  const { mkdir } = await import("node:fs/promises");
  await mkdir(dir, { recursive: true });
}
