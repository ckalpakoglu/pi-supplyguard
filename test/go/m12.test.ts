/**
 * M12: the named holes, closed.
 *
 * - A scoped GOPRIVATE/GONOSUMDB that covers the module being added is a
 *   checksum bypass for THAT module (SPEC 2.1's allowance, kept honest).
 * - A `docker://` tag in a workflow is mutable like an action tag; only a
 *   digest pins.
 * - A tracked file changed while no tool call was executing is attributed
 *   with its timing, on top of the next call's reconciliation.
 */
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { createGoAdapter } from "../../src/adapters/go/index.ts";
import { createAdapterRegistry } from "../../src/adapters/registry.ts";
import { createGenericAdapter } from "../../src/generic/index.ts";
import { inspectWorkflow } from "../../src/generic/github-actions.ts";
import { createRuntime, type SupplyGuardRuntime } from "../../src/index.ts";

const tempRoots: string[] = [];

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

const go = createGoAdapter({ env: { GOPROXY: "off" } });
const inspect = async (command: string) =>
  (
    await go.inspectToolCall(
      { toolName: "bash", input: { command } },
      { repoRoot: "/repo", profile: "standard", watchedPaths: [] },
    )
  ).events;

test("a GOPRIVATE scope covering the module being added is a checksum bypass", async () => {
  const events = await inspect("GOPRIVATE=github.com/foo/* go get github.com/foo/bar@v1.2.3");
  assert.ok(
    events.some((e) => e.eventClass === "ChecksumBypass"),
    "the add exempts itself from the checksum database",
  );

  const other = await inspect("GOPRIVATE=github.com/mycorp/* go get github.com/foo/bar@v1.2.3");
  assert.ok(
    !other.some((e) => e.eventClass === "ChecksumBypass"),
    "a scope that does not cover the module stays a normal add (SPEC 2.1)",
  );
});

test("a docker tag is mutable; a digest pins", () => {
  const workflow = [
    "jobs:",
    "  build:",
    "    steps:",
    "      - uses: docker://alpine:3",
    "",
  ].join("\n");
  const events = inspectWorkflow(".github/workflows/ci.yml", workflow, "hardened", {
    changed: true,
  });
  assert.equal(events.length, 1);
  assert.match(events[0]?.summary ?? "", /docker:\/\/alpine:3/);

  const pinned = inspectWorkflow(
    ".github/workflows/ci.yml",
    "jobs:\n  build:\n    steps:\n      - uses: docker://alpine@sha256:" + "a".repeat(64) + "\n",
    "hardened",
    { changed: true },
  );
  assert.deepEqual(pinned, []);
});

async function outOfBandHarness(): Promise<{
  runtime: SupplyGuardRuntime;
  ctx: never;
  repo: string;
  notices: string[];
  call(id: string, command: string): Promise<{ block?: boolean } | undefined>;
  result(id: string): void;
}> {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-oob-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-oob-home-"));
  tempRoots.push(repo, home);
  await writeFile(join(repo, "go.mod"), "module example.com/app\n\ngo 1.22\n");

  const notices: string[] = [];
  const runtime = createRuntime({
    home,
    env: {},
    registry: createAdapterRegistry([createGenericAdapter(), createGoAdapter({ env: { GOPROXY: "off" } })]),
  });
  const ctx = {
    cwd: repo,
    hasUI: true,
    mode: "tui" as const,
    ui: {
      select: async () => "Deny",
      confirm: async () => false,
      input: async () => "a reason",
      notify: (message: string) => {
        notices.push(message);
      },
    },
    sessionManager: { getSessionId: () => "session-1" },
  };
  return {
    runtime,
    ctx: ctx as never,
    repo,
    notices,
    call: (id: string, command: string) =>
      runtime.onToolCall({ toolName: "bash", toolCallId: id, input: { command } }, ctx as never),
    result: (id) =>
      runtime.onToolResult({ toolName: "bash", toolCallId: id, isError: false }, ctx as never),
  };
}

// fs.watch delivery is real inotify latency: no deterministic clock control
// exists for the platform, so this is the rule's integration exception.
const settle = (): Promise<void> =>
  // Executor form: the repo's TS lib predates Promise.withResolvers.
  new Promise((resolve) => {
    setTimeout(resolve, 250);
  });


test("a tracked file changed between tool calls is attributed with its timing", async () => {
  const h = await outOfBandHarness();
  await h.call("1", "ls");
  h.result("1");

  await writeFile(join(h.repo, "go.mod"), "module example.com/app\n\ngo 1.22\n\nrequire github.com/x/y v1.0.0\n");
  await settle();
  h.notices.length = 0;

  await h.call("2", "ls");
  assert.ok(
    h.notices.some((n) => /no tool call was running/.test(n)),
    "the write's timing is reported next to the reconciliation",
  );
});

test("a write made while a call executes is not out-of-band", async () => {
  const h = await outOfBandHarness();
  await h.call("1", "ls");
  h.result("1");
  await h.call("2", "ls"); // window opens; no result yet

  await writeFile(join(h.repo, "go.mod"), "module example.com/app\n\ngo 1.22\n\nrequire github.com/x/y v1.0.0\n");
  await settle();
  h.result("2");
  h.notices.length = 0;

  await h.call("3", "ls");
  assert.ok(
    !h.notices.some((n) => /no tool call was running/.test(n)),
    "attributed to the in-flight call; reconciliation handles it",
  );
});
