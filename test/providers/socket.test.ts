/**
 * Socket.dev integration through the Socket CLI (SPEC 13, 20, 23.3).
 *
 * Socket is ADDITIVE (SPEC 13.5), and most of what follows pins that: its
 * verdict can add a reason to refuse and can never remove one. The SPEC 23.3
 * contract table is exercised at the end, minus the Firewall rows, which are
 * deliberately out of scope (see `docs/KNOWN-GAPS.md`).
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { isSafeArgument } from "../../src/providers/socket/cli.ts";
import {
  createSocketEvidence,
  createSocketProvider,
  parseScoreDocument,
  readAlertSeverity,
  socketFindings,
  toPurl,
  type SocketArtifactResult,
} from "../../src/providers/socket/index.ts";
import type { SupplyChainEvent } from "../../src/core/events.ts";
import { createRuntime } from "../../src/index.ts";

const tempRoots: string[] = [];

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

const SCORE_OK = JSON.stringify({
  ok: true,
  data: {
    purl: "pkg:golang/github.com/foo/bar@v1.2.3",
    self: { purl: "x", score: { overall: 92 }, alerts: [], capabilities: [] },
    transitively: { score: { overall: 88 }, alerts: [], capabilities: [], dependencyCount: 3 },
  },
});

const SCORE_MALWARE = JSON.stringify({
  ok: true,
  data: {
    self: {
      score: { overall: 3 },
      alerts: [
        { name: "malware", severity: "critical" },
        { name: "installScript", severity: "middle" },
      ],
    },
    transitively: { score: { overall: 3 }, alerts: [], dependencyCount: 0 },
  },
});

test("a Go module becomes the purl the CLI documents", () => {
  assert.equal(
    toPurl("go", "github.com/foo/bar", "v1.2.3"),
    "pkg:golang/github.com/foo/bar@v1.2.3",
  );
  assert.equal(toPurl("cargo", "serde", "1.0.0"), undefined, "no mapping, no guess");
});

// SECURITY: arguments go to a process. A value that could be read as a flag is
// refused rather than escaped.
test("unsafe process arguments are refused", () => {
  assert.equal(isSafeArgument("pkg:golang/github.com/foo/bar@v1.2.3"), true);
  assert.equal(isSafeArgument("--json"), false, "a caller-supplied flag is not an argument");
  assert.equal(isSafeArgument("-rf"), false);
  assert.equal(isSafeArgument("a b"), false);
  assert.equal(isSafeArgument("a;rm -rf /"), false);
  assert.equal(isSafeArgument("a$(whoami)"), false);
  assert.equal(isSafeArgument(""), false);
});

test("a score document is read into alerts", () => {
  const clean = parseScoreDocument(SCORE_OK);
  assert.equal(clean.kind, "scanned");
  if (clean.kind === "scanned") {
    assert.deepEqual(clean.alerts, []);
    assert.equal(clean.overall, 92);
  }

  const bad = parseScoreDocument(SCORE_MALWARE);
  assert.equal(bad.kind, "scanned");
  if (bad.kind === "scanned") {
    assert.deepEqual(
      bad.alerts.map((a) => [a.name, a.severity]),
      [
        ["malware", "critical"],
        ["installScript", "moderate"],
      ],
    );
  }
});

test("Socket's own severity spelling is normalized", () => {
  assert.equal(readAlertSeverity("middle"), "moderate");
  assert.equal(readAlertSeverity("critical"), "critical");
  assert.equal(readAlertSeverity("high"), "high");
  assert.equal(readAlertSeverity(undefined), "unknown");
});

// SECURITY: "we could not tell" and "there is nothing wrong" are the two
// answers a security tool must never confuse.
test("an unrecognized document is unavailable, never a clean result", () => {
  for (const [label, body] of [
    ["not JSON", "socket: command failed"],
    ["an array", "[]"],
    ["no data", '{"ok":true}'],
  ] as const) {
    assert.equal(parseScoreDocument(body).kind, "unavailable", label);
  }

  const authFailure = parseScoreDocument(
    '{"ok":false,"message":"This command requires a Socket API token","cause":"try `socket login`"}',
  );
  assert.equal(authFailure.kind, "unavailable");
  if (authFailure.kind === "unavailable") {
    assert.match(authFailure.reason, /API token/, "the operator is told what to fix");
  }
});

test("the provider caches health and per-artifact answers", async () => {
  const calls: string[][] = [];
  const provider = createSocketProvider({
    run: async (args) => {
      calls.push([...args]);
      return { ok: true, stdout: args[0] === "--version" ? "1.1.163\n" : SCORE_OK };
    },
  });

  assert.deepEqual(await provider.health(), { ok: true, version: "1.1.163" });
  await provider.health();
  await provider.checkArtifact("go", "github.com/foo/bar", "v1.2.3");
  await provider.checkArtifact("go", "github.com/foo/bar", "v1.2.3");

  assert.deepEqual(calls, [
    ["--version"],
    ["package", "score", "pkg:golang/github.com/foo/bar@v1.2.3", "--json"],
  ]);
});

test("a CLI that is not installed is unavailable, not a pass", async () => {
  const provider = createSocketProvider({
    run: async () => ({ ok: false, stdout: "", reason: "the socket CLI is not installed or not on PATH" }),
  });
  const health = await provider.health();
  assert.equal(health.ok, false);
  assert.match(health.reason ?? "", /not installed/);
});

function findings(
  result: SocketArtifactResult,
  profile: "standard" | "hardened" | "paranoid",
  required = false,
) {
  return socketFindings(result, {
    profile,
    artifact: "github.com/foo/bar",
    version: "v1.2.3",
    required,
  });
}

test("a clean Socket result adds nothing at all", () => {
  for (const profile of ["standard", "hardened", "paranoid"] as const) {
    assert.deepEqual(findings({ kind: "scanned", alerts: [] }, profile, true), []);
  }
});

test("a critical Socket alert denies in every profile", () => {
  for (const profile of ["standard", "hardened", "paranoid"] as const) {
    const result = findings(
      { kind: "scanned", alerts: [{ name: "malware", severity: "critical" }] },
      profile,
    );
    assert.equal(result[0]?.decision, "deny", profile);
    assert.equal(result[0]?.origin, "external", "it reaches the decision as external evidence");
    assert.equal(result[0]?.overridable, undefined, "external denials are not waivable");
  }
});

test("a high alert asks below paranoid and denies in it", () => {
  const alerts = [{ name: "networkAccess", severity: "high" as const }];
  assert.equal(findings({ kind: "scanned", alerts }, "standard")[0]?.decision, "ask");
  assert.equal(findings({ kind: "scanned", alerts }, "hardened")[0]?.decision, "ask");
  assert.equal(findings({ kind: "scanned", alerts }, "paranoid")[0]?.decision, "deny");
});

test("an unavailable Socket denies only where it is required", () => {
  const unavailable: SocketArtifactResult = { kind: "unavailable", reason: "no API token" };
  assert.equal(findings(unavailable, "hardened", false)[0]?.decision, "warn");
  assert.equal(findings(unavailable, "hardened", true)[0]?.decision, "deny");
  assert.match(findings(unavailable, "paranoid", true)[0]?.message ?? "", /restore Socket/);
});

test("an ecosystem Socket cannot address is ignored unless it is required", () => {
  const unsupported: SocketArtifactResult = { kind: "unsupported", reason: "no purl mapping" };
  assert.deepEqual(findings(unsupported, "standard", false), []);
  assert.equal(findings(unsupported, "paranoid", true)[0]?.decision, "deny");
});

// SPEC 20: a provider that cannot pass its own health check authorizes nothing.
test("a failed health check speaks for the whole session", async () => {
  const evidence = createSocketEvidence(
    createSocketProvider({ run: async () => ({ ok: false, stdout: "", reason: "not installed" }) }),
    { requiredFor: (profile) => profile === "paranoid" },
  );

  const event: SupplyChainEvent = {
    eventClass: "DependencyAdd",
    ecosystem: "go",
    classification: "THIRD_PARTY_MUTATION",
    artifact: "github.com/foo/bar",
    version: "v1.2.3",
    summary: "adds a dependency",
  };

  assert.equal((await evidence([event], { profile: "hardened" }))[0]?.decision, "warn");
  assert.equal((await evidence([event], { profile: "paranoid" }))[0]?.decision, "deny");
});

test("events with no artifact are not sent to Socket at all", async () => {
  let called = false;
  const evidence = createSocketEvidence(
    createSocketProvider({
      run: async () => {
        called = true;
        return { ok: true, stdout: "1.1.163\n" };
      },
    }),
    { requiredFor: () => true },
  );

  const event: SupplyChainEvent = {
    eventClass: "LockfileMutation",
    ecosystem: "go",
    classification: "THIRD_PARTY_MUTATION",
    summary: "go.sum changed",
  };
  assert.deepEqual(await evidence([event], { profile: "paranoid" }), []);
  assert.equal(called, false, "nothing to score, nothing to run");
});

async function runtimeWithSocket(
  profile: string,
  score: string,
  options: {
    readonly healthy?: boolean;
    readonly corpus?: string;
    /** Answer to an override prompt. Defaults to taking the override. */
    readonly override?: "Override once" | "Keep the denial";
  } = {},
) {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-socket-repo-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-socket-home-"));
  tempRoots.push(repo, home);
  await writeFile(join(repo, ".supplyguard.yaml"), `version: 1\nprofile: ${profile}\n`);
  await writeFile(join(repo, "go.mod"), "module m\n\ngo 1.22\n");
  await mkdir(join(repo, "vendor"), { recursive: true });
  await writeFile(join(repo, "vendor", "modules.txt"), "");
  if (options.corpus !== undefined) {
    await writeFile(join(repo, ".supplyguard-trust.yaml"), options.corpus);
  }

  const prompts: string[] = [];
  const runtime = createRuntime({
    home,
    env: {},
    proxy: { env: { GOPROXY: "off" } },
    osv: { env: { GOPROXY: "off" } },
    socket: {
      run: async (args) =>
        args[0] === "--version"
          ? options.healthy === false
            ? { ok: false, stdout: "", reason: "the socket CLI is not installed or not on PATH" }
            : { ok: true, stdout: "1.1.163\n" }
          : { ok: true, stdout: score },
    },
  });

  const ctx = {
    cwd: repo,
    hasUI: true,
    mode: "tui" as const,
    ui: {
      select: async (title: string, choices: readonly string[]) => {
        prompts.push(title);
        return choices.includes("Override once")
          ? (options.override ?? "Override once")
          : "Approve once";
      },
      confirm: async () => false,
      input: async () => "a written reason",
      notify: () => {},
    },
    sessionManager: { getSessionId: () => "session-1" },
  };

  return {
    prompts,
    run: async (module = "github.com/foo/bar") => {
      await runtime.justifyTool(
        {
          module,
          version: "v1.2.3",
          purpose: "test",
          stdlibConsidered: true,
          stdlibInsufficientReason: "none",
        },
        ctx as never,
      );
      return runtime.onToolCall(
        { toolName: "bash", toolCallId: "1", input: { command: `go get ${module}@v1.2.3` } },
        ctx as never,
      );
    },
  };
}

test("Socket clean plus local clean continues to the approval path", async () => {
  const h = await runtimeWithSocket("hardened", SCORE_OK);
  assert.equal(await h.run(), undefined);
});

test("Socket deny blocks a dependency the local checks were happy with", async () => {
  const h = await runtimeWithSocket("standard", SCORE_MALWARE);
  const blocked = await h.run();
  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /malware/);
});

// SPEC 13.5, the invariant that matters most: a clean external result cannot
// remove a local reason to refuse.
test("Socket clean does not rescue a local repository squat", async () => {
  const h = await runtimeWithSocket("hardened", SCORE_OK, {
    corpus: "version: 1\nprotected:\n  go:\n    modules:\n      - github.com/google/uuid\n",
    override: "Keep the denial",
  });
  const blocked = await h.run("github.com/random-owner/uuid");
  assert.equal(blocked?.block, true, "local policy wins, whatever Socket says");
  assert.match(blocked?.reason ?? "", /repository name of the protected identity/);
  assert.ok(
    h.prompts.some((prompt) => prompt.includes("override this denial")),
    "a clean Socket result does not remove the local denial; it still had to be waived",
  );
});

// SPEC 13.4: paranoid requires an artifact evaluation for every new dependency.
test("paranoid denies a new dependency when Socket cannot answer", async () => {
  const h = await runtimeWithSocket("paranoid", SCORE_OK, { healthy: false });
  const blocked = await h.run();
  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /health check/);
});

test("hardened continues with a warning when Socket is absent", async () => {
  const h = await runtimeWithSocket("hardened", SCORE_OK, { healthy: false });
  assert.equal(await h.run(), undefined, "local hardened policy remains in force");
});

// SPEC 13.4 / 25: "Already-approved vendored dependencies may continue to
// build and test offline when the graph is unchanged." A paranoid session with
// no Socket at all must still be able to work in a vendored repository — the
// gate is on new trust, not on the repository.
test("paranoid builds and tests offline in a vendored repo with no Socket", async () => {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-offline-repo-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-offline-home-"));
  tempRoots.push(repo, home);
  await writeFile(join(repo, ".supplyguard.yaml"), "version: 1\nprofile: paranoid\n");
  await writeFile(join(repo, "go.mod"), "module m\n\ngo 1.22\n");
  await mkdir(join(repo, "vendor"), { recursive: true });
  await writeFile(join(repo, "vendor", "modules.txt"), "");

  const runtime = createRuntime({
    home,
    env: {},
    proxy: { env: { GOPROXY: "off" } },
    osv: { env: { GOPROXY: "off" } },
    // Nothing is reachable: no Socket, no proxy, no OSV.
    socket: { run: async () => ({ ok: false, stdout: "", reason: "not installed" }) },
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

  for (const command of ["go build ./...", "go test ./...", "ls", "git status"]) {
    assert.equal(
      await runtime.onToolCall(
        { toolName: "bash", toolCallId: "1", input: { command } },
        ctx as never,
      ),
      undefined,
      `${command} must work offline against a vendored tree`,
    );
  }

  // ... while a NEW trust decision still fails closed.
  const blocked = await runtime.onToolCall(
    { toolName: "bash", toolCallId: "2", input: { command: "go get github.com/foo/bar@v1.2.3" } },
    ctx as never,
  );
  assert.equal(blocked?.block, true);
});
