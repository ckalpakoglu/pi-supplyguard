/**
 * D26 regression: repository signals are gated by `signals.enabled` alone.
 * They used to sit behind the Jev early returns, so `signals.enabled: true`
 * with Jev off (or no key) was silently inert -- an enabled control doing
 * nothing. Injected transport; no network.
 */
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { createRuntime } from "../../src/index.ts";

const tempRoots: string[] = [];
after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function signalsHarness(config: string) {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-d26-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-d26-home-"));
  tempRoots.push(repo, home);
  await writeFile(join(repo, ".supplyguard.yaml"), config);
  await writeFile(
    join(repo, "go.mod"),
    "module lab.example/app\n\ngo 1.24\n",
  );
  const fetched: string[] = [];
  const runtime = createRuntime({
    home,
    env: {}, // deliberately no TYPESAFE_API_KEY: Jev cannot be on
    signals: {
      fetch: async (url) => {
        fetched.push(url);
        return { status: 301, location: "https://api.github.com/repo/newowner" };
      },
    },
  });
  const ctx = {
    cwd: repo,
    hasUI: false,
    mode: "print" as const,
    ui: { select: async () => undefined, confirm: async () => false, input: async () => undefined, notify: () => {} },
    sessionManager: { getSessionId: () => "s" },
  };
  const outcome = await runtime.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "go get github.com/old/repo@v1.0.0" } },
    ctx as never,
  );
  return { fetched, outcome };
}

test("signals.enabled works with Jev off and no key (D26)", async () => {
  const { fetched, outcome } = await signalsHarness("version: 1\nsignals:\n  enabled: true\n");
  assert.ok(
    fetched.some((url) => url.includes("api.github.com/repos/old/repo")),
    `the signals provider was consulted: ${JSON.stringify(fetched)}`,
  );
  // Headless: the deny headline is the missing justification (SPEC 11.2);
  // the transfer signal rides as a finding, unit-tested in signals.test.ts.
  assert.equal(outcome?.block, true);
});

test("signals stay off when not enabled", async () => {
  const { fetched } = await signalsHarness("version: 1\n");
  assert.deepEqual(fetched, []);
});
