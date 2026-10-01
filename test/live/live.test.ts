/**
 * Live provider contract tests (M14, PLAN-ZERO-DAY P5).
 *
 * D18's lesson: every provider test injected its runner, and the real Socket
 * CLI had never run. These tests are the structural fix -- they exercise the
 * real proxy, the real OSV and the real Socket CLI, and they are the only
 * tests in the suite allowed to touch the network.
 *
 * They run ONLY with LIVE=1 (the weekly CI job); the normal suite stays
 * hermetic. No credentials are required: the Go proxy and OSV are public, and
 * the Socket part self-skips when the CLI is absent.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { lookupReleaseDate } from "../../src/adapters/go/proxy.ts";
import { lookupVulnerabilities } from "../../src/adapters/go/osv.ts";
import { createSocketProvider } from "../../src/providers/socket/index.ts";

const live = process.env.LIVE === "1";

test("the Go proxy answers a real publication date", { skip: !live }, async () => {
  const lookup = await lookupReleaseDate("github.com/google/uuid", "v1.6.0", {});
  assert.equal(lookup.kind, "known");
  if (lookup.kind === "known") {
    assert.ok(lookup.publishedAt.getTime() > 0);
    // v1.6.0 was published in 2024; a healthy answer is not from the 1970s
    // and not from the future.
    assert.ok(lookup.publishedAt.getFullYear() >= 2024);
  }
});

test("OSV answers a real advisory query", { skip: !live }, async () => {
  const lookup = await lookupVulnerabilities("golang.org/x/net", "v0.9.0", {});
  assert.notEqual(lookup.kind, "unavailable");
});

test("the installed Socket CLI answers health and a score", { skip: !live }, async () => {
  const provider = createSocketProvider();
  const health = await provider.health();
  if (!health.ok) return; // CLI absent on this runner: nothing to contract-test
  assert.match(health.version ?? "", /^\d+\.\d+/);

  const result = await provider.checkArtifact("go", "github.com/google/uuid", "v1.6.0");
  assert.equal(result.kind, "scanned", JSON.stringify(result));
});
