/**
 * Is the Jev integration actually wired? (M10/M14 follow-up.)
 *
 * The provider has unit tests; this file proves the WIRING: `jev.enabled` in
 * project configuration plus a key in the environment makes the runtime's
 * external-evidence path call the analyzer with a locally resolvable module
 * source, and the finding reaches the human's approval prompt. Transport is
 * injected — no test reaches the network — and every "off" spelling stays
 * silent.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
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

const VENDORED = "package evil\n\nfunc init() {\n\thttp.Get(\"https://collector.example/ping\")\n}\n";

interface Harness {
  repo: string;
  prompts: string[];
  call(command: string): Promise<{ block?: boolean } | undefined>;
}

async function harness(options: {
  config?: string;
  env?: Record<string, string | undefined>;
  post?: (url: string, body: unknown, apiKey: string) => Promise<unknown>;
}): Promise<Harness> {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-jevwire-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-jevwire-home-"));
  tempRoots.push(repo, home);

  if (options.config !== undefined) {
    await writeFile(join(repo, ".supplyguard.yaml"), options.config);
  }
  await writeFile(join(repo, "go.mod"), "module example.com/app\n\ngo 1.22\n\nrequire github.com/evil/pkg v0.0.1\n");
  await writeFile(join(repo, "go.sum"), "github.com/evil/pkg v0.0.1 h1:abc=\ngithub.com/evil/pkg v0.0.1/go.mod h1:def=\n");
  const vendorDir = join(repo, "vendor", "github.com", "evil", "pkg");
  await mkdir(vendorDir, { recursive: true });
  await writeFile(join(vendorDir, "beacon.go"), VENDORED);
  await writeFile(join(repo, "vendor", "modules.txt"), "# github.com/evil/pkg v0.0.1\n## explicit; go 1.22\ngithub.com/evil/pkg\n");

  const prompts: string[] = [];
  const runtime = createRuntime({
    home,
    env: options.env ?? {},
    ...(options.post === undefined ? {} : { jev: { post: options.post } }),
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

  await runtime.justifyTool(
    {
      module: "github.com/evil/pkg",
      version: "v0.0.1",
      purpose: "wiring smoke",
      stdlibConsidered: true,
      stdlibInsufficientReason: "none",
    },
    ctx as never,
  );

  return {
    repo,
    prompts,
    call: (command: string) =>
      runtime.onToolCall({ toolName: "bash", toolCallId: "1", input: { command } }, ctx as never),
  };
}

test("jev.enabled + key: the analyzer is consulted and its finding reaches the prompt", async () => {
  const calls: { url: string; body: unknown; apiKey: string }[] = [];
  const h = await harness({
    config: "version: 1\njev:\n  enabled: true\n",
    env: { TYPESAFE_API_KEY: "test-key" },
    post: async (url, body, apiKey) => {
      calls.push({ url, body, apiKey });
      return { answers: [{ type: "noul", id: "malicious", p: 0.95 }] };
    },
  });

  await h.call("go get github.com/evil/pkg@v0.0.1");
  assert.equal(calls.length, 1, "exactly one question, for the one artifact");
  assert.equal(calls[0]?.apiKey, "test-key");
  assert.match(calls[0]?.url ?? "", /\/v1\/systemone$/);
  assert.match(
    String((calls[0]?.body as { state?: string }).state),
    /package evil/,
    "the module's vendored source is what gets sent",
  );

  const prompt = h.prompts.join("\n\n");
  assert.match(prompt, /Jev rates github\.com\/evil\/pkg@v0\.0\.1 malicious with p=0\.95/);
  // The local scan's finding is present too: additive evidence, not replacement.
  assert.match(prompt, /network call inside func init/);
});

test("every off spelling stays silent", async () => {
  const calls: { url: string }[] = [];
  const post = async (url: string) => {
    calls.push({ url });
    return { answers: [{ type: "noul", id: "malicious", p: 0.95 }] };
  };

  // Config off, key present.
  const offByConfig = await harness({ env: { TYPESAFE_API_KEY: "test-key" }, post });
  await offByConfig.call("go get github.com/evil/pkg@v0.0.1");
  // Config on, key absent.
  const offByKey = await harness({ config: "version: 1\njev:\n  enabled: true\n", post });
  await offByKey.call("go get github.com/evil/pkg@v0.0.1");

  assert.deepEqual(calls, [], "no question is asked unless both config and key say yes");
});

test("JEV_API_KEY is honored as a fallback spelling", async () => {
  const keys: string[] = [];
  const h = await harness({
    config: "version: 1\njev:\n  enabled: true\n",
    env: { JEV_API_KEY: "legacy-key" },
    post: async (_url, _body, apiKey) => {
      keys.push(apiKey);
      return { answers: [{ type: "noul", id: "malicious", p: 0.1 }] };
    },
  });
  await h.call("go get github.com/evil/pkg@v0.0.1");
  assert.deepEqual(keys, ["legacy-key"]);
});
