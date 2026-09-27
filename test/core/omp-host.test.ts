/**
 * omp tool shapes through the real hook path.
 *
 * omp's bash tool takes `env` and `cwd` beside `command`, and its `write` tool
 * sends `content` to a running process's stdin when the path is `proc://…`.
 * Each can change what runs without changing the `command` string adapters
 * read, so each must be inspected as the shell command it is equivalent to.
 */
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { createGoAdapter } from "../../src/adapters/go/index.ts";
import { createAdapterRegistry } from "../../src/adapters/registry.ts";
import { createGenericAdapter } from "../../src/generic/index.ts";
import { createRuntime } from "../../src/index.ts";

const tempRoots: string[] = [];

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

const BASE_GO_MOD = `module example.com/app

go 1.22

require github.com/foo/bar v1.2.3
`;

type Hook = (
  toolName: string,
  input: Record<string, unknown>,
) => Promise<{ block?: boolean; reason?: string } | undefined>;

/** A headless omp session: any ASK fails closed, so only ALLOW passes. */
async function ompSession(): Promise<Hook> {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-omp-repo-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-omp-home-"));
  tempRoots.push(repo, home);
  await writeFile(join(repo, "go.mod"), BASE_GO_MOD);

  const runtime = createRuntime({
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
  let seq = 0;
  return (toolName, input) =>
    runtime.onToolCall({ toolName, toolCallId: String(++seq), input }, ctx as never);
}

test("omp bash env overrides are inspected like prefix assignments", async () => {
  const hook = await ompSession();
  for (const env of [
    { GOSUMDB: "off" },
    { GOFLAGS: "-mod=mod -insecure" },
    // A quote in one value must not swallow the next assignment.
    { X: "a'b", GONOSUMDB: "example.com" },
  ]) {
    const result = await hook("bash", { command: "go build ./...", name: "svc", env });
    assert.equal(result?.block, true, JSON.stringify(env));
  }

  assert.equal(
    await hook("bash", { command: "go build ./...", name: "svc", env: { FOO: "bar" } }),
    undefined,
  );
});

test("omp bash cwd cannot hide the command", async () => {
  const hook = await ompSession();
  const result = await hook("bash", {
    command: "go get github.com/foo/bar@latest",
    cwd: "it's here",
  });
  assert.equal(result?.block, true);

  assert.equal(await hook("bash", { command: "ls", cwd: "sub dir" }), undefined);
});

test("stdin written to a proc:// service is inspected as a command", async () => {
  const hook = await ompSession();
  for (const path of ["proc://sh", "[proc://sh#1A2B]"]) {
    const result = await hook("write", {
      path,
      content: "go get github.com/foo/bar@latest\n",
    });
    assert.equal(result?.block, true, path);
  }

  // A file that merely contains a command is data, not something being run.
  assert.equal(
    await hook("write", {
      path: "notes/go-get.md",
      content: "go get github.com/foo/bar@latest",
    }),
    undefined,
  );
  assert.equal(await hook("write", { path: "proc://sh/kill" }), undefined);
});
