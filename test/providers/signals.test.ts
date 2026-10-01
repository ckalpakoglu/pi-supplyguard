/**
 * Repository signals (M14): the compromised-release shape, opt-in.
 * Injected transport only; no test reaches the network.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { createRepoSignalsProvider } from "../../src/providers/signals/index.ts";

const now = new Date("2026-10-01T00:00:00Z");

function providerWith(answer: () => Promise<unknown>) {
  return createRepoSignalsProvider({ fetch: answer, now: () => now });
}

test("a transferred repository is the strongest signal", async () => {
  const provider = providerWith(async () => ({ status: 301, location: "https://api.github.com/repo/new" }));
  const findings = await provider.evidenceFor("github.com/old/repo", "v1.0.0");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.decision, "ask");
  assert.match(findings[0]?.message ?? "", /different owner/);
});

test("an archived repository releasing a version is flagged", async () => {
  const provider = providerWith(async () => ({
    owner: { login: "old" },
    archived: true,
    pushed_at: "2020-01-01T00:00:00Z",
    stargazers_count: 5000,
  }));
  const findings = await provider.evidenceFor("github.com/old/repo", "v1.0.0");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.code, "signal:archived");
});

test("a fresh repository with no history is first-mover risk", async () => {
  const provider = providerWith(async () => ({
    owner: { login: "new" },
    archived: false,
    pushed_at: "2026-09-28T00:00:00Z",
    stargazers_count: 1,
  }));
  const findings = await provider.evidenceFor("github.com/new/repo", "v0.0.1");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.code, "signal:fresh-repo");
});

test("an ordinary healthy repository says nothing", async () => {
  const provider = providerWith(async () => ({
    owner: { login: "google" },
    archived: false,
    pushed_at: "2026-09-28T00:00:00Z",
    stargazers_count: 5000,
  }));
  assert.deepEqual(await provider.evidenceFor("github.com/google/uuid", "v1.6.0"), []);
});

test("an unreachable API withholds nothing, and answers are cached per repo", async () => {
  let calls = 0;
  const provider = providerWith(async () => {
    calls += 1;
    throw new Error("HTTP 403");
  });
  assert.deepEqual(await provider.evidenceFor("github.com/a/b", "v1.0.0"), []);
  assert.deepEqual(await provider.evidenceFor("github.com/a/b", "v2.0.0"), []);
  assert.equal(calls, 1);

  // Not a host/owner/repo path: no request at all.
  assert.deepEqual(await provider.evidenceFor("short/name", "v1"), []);
  assert.equal(calls, 1);
});
