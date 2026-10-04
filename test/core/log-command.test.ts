/**
 * `/supplyguard-log [n]` (follow-up to the live Pi session): the audit trail,
 * readable from inside the agent — in a scrollable popup when the host has
 * one (Pi's `ui.editor`), as a notification otherwise.
 */
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { createRuntime, type SupplyGuardRuntime } from "../../src/index.ts";

const tempRoots: string[] = [];

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

const GO_MOD = "module example.com/app\n\ngo 1.22\n\nrequire github.com/foo/bar v1.2.3\n";

function contextFor(repo: string, capture: { popup?: string; notices: string[] }) {
  return {
    cwd: repo,
    hasUI: true,
    mode: "tui" as const,
    ui: {
      select: async () => "Deny",
      confirm: async () => false,
      input: async () => "a reason",
      notify: (message: string) => {
        capture.notices.push(message);
      },
      editor: async (title: string, prefill?: string) => {
        capture.popup = `${title}\n${prefill ?? ""}`;
        return undefined;
      },
    },
    sessionManager: { getSessionId: () => "session-1" },
  };
}

test("the last n audit records render in the popup, newest last", async () => {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-log-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-log-home-"));
  tempRoots.push(repo, home);
  await writeFile(join(repo, "go.mod"), GO_MOD);

  const capture: { popup?: string; notices: string[] } = { notices: [] };
  const runtime: SupplyGuardRuntime = createRuntime({ home, env: {} });
  const ctx = contextFor(repo, capture);

  // Produce audited records: an allowed (audited) network fetch, and a
  // denial with findings. Harmless calls like `ls` are deliberately not
  // audited, so they would not appear here.
  await runtime.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "curl -o data.json https://example.com/data" } },
    ctx as never,
  );
  await runtime.onToolCall(
    { toolName: "bash", toolCallId: "2", input: { command: "go get github.com/x/y@latest" } },
    ctx as never,
  );

  await runtime.logCommand("10", ctx as never);
  assert.ok(capture.popup !== undefined, "the popup was used when the host has one");
  const lines = (capture.popup ?? "").split("\n");
  assert.match(capture.popup ?? "", /SupplyGuard audit — last/);
  assert.match(capture.popup ?? "", /tool-call bash → deny/);
  assert.match(capture.popup ?? "", /floating/i);
  assert.ok(lines.length >= 3, "one line per record, plus the title");
});

test("without a popup the log falls back to a notification, and empty stays honest", async () => {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-log-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-log-home-"));
  tempRoots.push(repo, home);
  await writeFile(join(repo, "go.mod"), GO_MOD);

  const capture: { notices: string[] } = { notices: [] };
  const ctx = {
    cwd: repo,
    hasUI: true,
    mode: "tui" as const,
    ui: {
      select: async () => "Deny",
      confirm: async () => false,
      input: async () => "a reason",
      notify: (message: string) => {
        capture.notices.push(message);
      },
      // No editor: print-mode hosts and older Pi builds.
    },
    sessionManager: { getSessionId: () => "session-1" },
  };
  const runtime: SupplyGuardRuntime = createRuntime({ home, env: {} });

  await runtime.logCommand("", ctx as never);
  assert.match(capture.notices.join("\n"), /no audit records yet/);

  await runtime.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "curl -o data.json https://example.com/data" } },
    ctx as never,
  );
  capture.notices.length = 0;
  await runtime.logCommand("", ctx as never);
  assert.match(capture.notices.join("\n"), /tool-call bash → allow/);
  assert.match(capture.notices.join("\n"), /NetworkRequirement|fetches from the network/);
});
