/**
 * Content evidence through the real runtime (M10).
 *
 * The zero-day claim rests on this: a module whose malicious content no
 * database knows produces findings the human can read, and a module whose
 * source is not locally resolvable says so out loud instead of looking clean.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { createGoAdapter } from "../../src/adapters/go/index.ts";
import { createAdapterRegistry } from "../../src/adapters/registry.ts";
import { createGenericAdapter } from "../../src/generic/index.ts";
import { createRuntime, type SupplyGuardRuntime } from "../../src/index.ts";

const tempRoots: string[] = [];

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

const MALICIOUS = [
  "package pkg",
  "",
  "func init() {",
  "  http.Get(\"https://collector.example/ping\")",
  "}",
].join("\n");

interface Harness {
  repo: string;
  runtime: SupplyGuardRuntime;
  ctx: never;
  prompts: string[];
  notices: string[];
  call(command: string): Promise<{ block?: boolean; reason?: string } | undefined>;
  status(): Promise<void>;
}

async function harness(vendor?: Record<string, string>): Promise<Harness> {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-content-e2e-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-content-home-"));
  tempRoots.push(repo, home);

  let goMod = "module example.com/app\n\ngo 1.22\n\nrequire github.com/foo/bar v1.2.3\n";
  let modulesTxt = "";
  if (vendor !== undefined) {
    goMod = "module example.com/app\n\ngo 1.22\n\nrequire github.com/evil/pkg v0.0.1\n";
    modulesTxt = "# github.com/evil/pkg v0.0.1\n## explicit; go 1.22\ngithub.com/evil/pkg\n";
    const vendorDir = join(repo, "vendor", "github.com", "evil", "pkg");
    await mkdir(vendorDir, { recursive: true });
    for (const [name, body] of Object.entries(vendor)) {
      await writeFile(join(vendorDir, name), body);
    }
    await writeFile(join(repo, "vendor", "modules.txt"), modulesTxt);
  }
  await writeFile(join(repo, "go.mod"), goMod);

  const prompts: string[] = [];
  const notices: string[] = [];
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
    hasUI: true,
    mode: "tui" as const,
    ui: {
      select: async (title: string) => {
        prompts.push(title);
        return "Deny";
      },
      confirm: async () => false,
      input: async () => "a reason",
      notify: (message: string) => {
        notices.push(message);
      },
    },
    sessionManager: { getSessionId: () => "session-1" },
  };

  return {
    repo,
    runtime,
    ctx: ctx as never,
    prompts,
    notices,
    call: (command: string) =>
      runtime.onToolCall({ toolName: "bash", toolCallId: "1", input: { command } }, ctx as never),
    status: () => runtime.statusCommand("", ctx as never),
  };
}

test("a vendored dependency with import-time egress reaches the approval prompt", async () => {
  const h = await harness({ "beacon.go": MALICIOUS });
  await h.call("ls"); // baseline; may ask about enforcing the vendor model

  const justified = await h.runtime.justifyTool(
    {
      module: "github.com/evil/pkg",
      version: "v0.0.1",
      purpose: "content evidence smoke",
      stdlibConsidered: true,
      stdlibInsufficientReason: "no stdlib equivalent",
    },
    h.ctx,
  );
  assert.notEqual(justified.isError, true, JSON.stringify(justified.content));

  await h.call("go get github.com/evil/pkg@v0.0.1");
  assert.match(
    h.prompts.join("\n\n"),
    /network call inside func init/,
    "the human sees the code-level finding, not just a module name",
  );
});

test("a dependency whose source is not locally resolvable is denied for the missing justification", async () => {
  const h = await harness();
  await h.call("ls");
  const blocked = await h.call("go get github.com/never/fetched@v1.0.0");
  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /supplyguard_justify_dependency/);
});

test("status shows the analyzer state and the fatigue metric", async () => {
  const h = await harness();
  await h.call("ls");

  const justified = await h.runtime.justifyTool(
    {
      module: "github.com/foo/bar",
      version: "v9.9.9",
      purpose: "fatigue metric smoke",
      stdlibConsidered: true,
      stdlibInsufficientReason: "no stdlib equivalent",
    },
    h.ctx,
  );
  assert.notEqual(justified.isError, true, JSON.stringify(justified.content));

  await h.call("go get github.com/foo/bar@v9.9.9");
  assert.ok(h.prompts.length > 0, "one approval gate was put to the human");

  h.notices.length = 0;
  await h.status();
  const status = h.notices.join("\n");
  assert.match(status, /Jev analyzer\s+off/);
  assert.match(status, /Approvals asked\s+\d+ this session \(fatigue metric\)/);
});
