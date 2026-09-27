/**
 * `go generate` executes the `//go:generate` directives declared in source —
 * arbitrary commands, in checked-out or vendored files, and the classic shape
 * installs a tool on the spot:
 *
 *     //go:generate go run golang.org/x/tools/cmd/stringer@latest
 *
 * KNOWN-GAPS §1.9 recorded it as merely "capable"; it is a third-party
 * execution the command gate would otherwise never see.
 */
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { analyzeCommand } from "../../src/adapters/go/commands.ts";
import { createGoAdapter } from "../../src/adapters/go/index.ts";
import { createAdapterRegistry } from "../../src/adapters/registry.ts";
import { createGenericAdapter } from "../../src/generic/index.ts";
import { createRuntime, type SupplyGuardRuntime } from "../../src/index.ts";

const tempRoots: string[] = [];

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

test("go generate is a third-party execution, however it is wrapped", () => {
  for (const command of [
    "go generate ./...",
    "sh -c 'go generate ./...'",
    "cd pkg && go generate ./...",
    "env FOO=x go generate ./...",
  ]) {
    const analysis = analyzeCommand(command);
    const op = analysis.operations.find((o) => o.eventClass === "ThirdPartyExecution");
    assert.ok(op !== undefined, `must be a third-party execution: ${command}`);
    assert.match(op.summary, /go:generate/);
    assert.equal(analysis.classification, "THIRD_PARTY_CAPABLE", command);
  }
});

test("build-shaped subcommands are still merely capable", () => {
  for (const command of ["go build ./...", "go test ./...", "go vet ./..."]) {
    assert.deepEqual(
      analyzeCommand(command).operations.map((o) => o.eventClass),
      [],
      command,
    );
  }
});

test("a headless session cannot run go generate", async () => {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-generate-repo-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-generate-home-"));
  tempRoots.push(repo, home);
  await writeFile(join(repo, "go.mod"), "module example.com/app\n\ngo 1.22\n");

  const runtime: SupplyGuardRuntime = createRuntime({
    home,
    env: {},
    registry: createAdapterRegistry([
      createGenericAdapter(),
      createGoAdapter({ env: { GOPROXY: "off" } }),
    ]),
  });
  const ctx = {
    cwd: repo,
    hasUI: false,
    mode: "print" as const,
    ui: {
      select: async () => undefined,
      confirm: async () => false,
      input: async () => undefined,
      notify: () => {},
    },
    sessionManager: { getSessionId: () => "session-1" },
  };

  const outcome = await runtime.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "go generate ./..." } },
    ctx as never,
  );
  assert.equal(outcome?.block, true);
  assert.match(outcome?.reason ?? "", /Not approved by a human/);
});
