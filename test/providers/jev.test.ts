/**
 * The optional Jev analyzer (M10; KNOWN-GAPS 1.15).
 *
 * Every test injects the transport: the suite reaches no network, and no key
 * is ever required. What is pinned here is the request shape (verified against
 * the published TypeSafe evaluation API), the ASK cap while experimental, and
 * the fail-warn-not-deny posture of an absent provider.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { createJevAnalyzer } from "../../src/providers/jev/index.ts";

const tempRoots: string[] = [];

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function moduleDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "supplyguard-jev-"));
  tempRoots.push(dir);
  await writeFile(join(dir, "x.go"), "package pkg\n\nfunc F() {}\n");
  return dir;
}

test("a high-confidence malicious verdict contributes at most an ASK", async () => {
  const seen: unknown[] = [];
  const analyzer = createJevAnalyzer({
    enabled: true,
    apiKey: "test-key",
    post: async (_url, body, key) => {
      seen.push({ body, key });
      return { answers: [{ type: "noul", id: "malicious", p: 0.93 }] };
    },
  });
  const findings = await analyzer.evidenceFor({
    artifact: "github.com/foo/bar",
    version: "v1.2.3",
    source: await moduleDir(),
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.decision, "ask", "experimental cap: the human decides");
  assert.match(findings[0]?.message ?? "", /p=0\.93/);

  // The request shape is the contract with the API.
  const first = seen[0] as { body: Record<string, unknown>; key: string };
  assert.equal(first.key, "test-key");
  assert.equal((first.body as { model?: string }).model, "jev-latest");
  const questions = (first.body as { questions?: { type: string }[] }).questions ?? [];
  assert.equal(questions[0]?.type, "noul");
  assert.match(String((first.body as { state?: string }).state), /package pkg/);
});

test("a low probability means no finding, and the verdict is cached", async () => {
  let calls = 0;
  const analyzer = createJevAnalyzer({
    enabled: true,
    apiKey: "k",
    post: async () => {
      calls += 1;
      return { answers: [{ type: "noul", id: "malicious", p: 0.11 }] };
    },
  });
  const source = await moduleDir();
  const target = { artifact: "github.com/foo/bar", version: "v1.2.3", source };

  assert.deepEqual(await analyzer.evidenceFor(target), []);
  assert.deepEqual(await analyzer.evidenceFor(target), []);
  assert.equal(calls, 1, "one question per module@version");
});

test("a failing provider warns and vouches for nothing", async () => {
  const analyzer = createJevAnalyzer({
    enabled: true,
    apiKey: "k",
    post: async () => {
      throw new Error("HTTP 503");
    },
  });
  const findings = await analyzer.evidenceFor({
    artifact: "github.com/foo/bar",
    version: "v1.2.3",
    source: await moduleDir(),
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.decision, "warn");
  assert.equal(findings[0]?.code, "jev-unavailable");
});

test("a disabled analyzer does nothing, even with a key", async () => {
  const analyzer = createJevAnalyzer({ enabled: false, apiKey: "k" });
  assert.deepEqual(
    await analyzer.evidenceFor({
      artifact: "a",
      version: "v1",
      source: await moduleDir(),
    }),
    [],
  );
});
