/**
 * Dependency justification (SPEC 11.2, 17.1, 17.2).
 *
 * The agent supplies the rationale; a human still decides. These tests hold
 * both halves: an unjustified dependency never reaches a human, and a recorded
 * justification is evidence at the gate rather than a way past it.
 */
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import {
  createJustificationStore,
  JUSTIFY_TOOL,
  JUSTIFY_TOOL_PARAMETERS,
  needsJustification,
  parseJustification,
} from "../../src/core/justification.ts";
import type { SupplyChainEvent } from "../../src/core/events.ts";
import { createRuntime, type SupplyGuardRuntime } from "../../src/index.ts";

const tempRoots: string[] = [];

async function tempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  tempRoots.push(dir);
  return dir;
}

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

const VALID = {
  module: "github.com/foo/bar",
  version: "v1.7.2",
  purpose: "structured logging with levels",
  stdlibConsidered: true,
  stdlibInsufficientReason: "log/slog lacks the sink we need",
};

const AT = "2026-09-02T00:00:00.000Z";

function event(over: Partial<SupplyChainEvent> = {}): SupplyChainEvent {
  return {
    eventClass: "DependencyAdd",
    ecosystem: "go",
    classification: "THIRD_PARTY_MUTATION",
    artifact: "github.com/foo/bar",
    version: "v1.7.2",
    summary: "adds a dependency",
    ...over,
  };
}

// ---------------------------------------------------------------------------
// Which events need one
// ---------------------------------------------------------------------------

test("new trust decisions need a justification; removals and unnamed events do not", () => {
  for (const eventClass of [
    "DependencyAdd",
    "DependencyUpgrade",
    "DependencyDowngrade",
    "DependencyReplace",
    "ToolInstall",
    "ToolUpgrade",
    "ThirdPartyExecution",
  ] as const) {
    assert.equal(needsJustification(event({ eventClass })), true, eventClass);
  }

  // Removal reduces third-party surface; demanding a rationale to take a
  // dependency OUT would point the friction the wrong way.
  assert.equal(needsJustification(event({ eventClass: "DependencyRemove" })), false);
  assert.equal(needsJustification(event({ eventClass: "LockfileMutation" })), false);
  assert.equal(needsJustification(event({ eventClass: "VendorDrift" })), false);

  // Nothing to justify when the artifact or version cannot be named; the
  // exact-version rules deny those long before this point.
  const { artifact: _artifact, ...unnamed } = event();
  const { version: _version, ...unversioned } = event();
  assert.equal(needsJustification(unnamed), false);
  assert.equal(needsJustification(unversioned), false);
});

// ---------------------------------------------------------------------------
// The store is one-shot and version-scoped (SPEC 11.3, 17.2)
// ---------------------------------------------------------------------------

test("a justification covers one artifact at one version, once", () => {
  const store = createJustificationStore();
  const parsed = parseJustification(VALID, AT);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;

  store.record(parsed.justification);
  assert.equal(store.peek("github.com/foo/bar", "v1.7.2")?.purpose, VALID.purpose);
  assert.equal(store.peek("github.com/foo/bar", "v1.7.3"), undefined, "a version change is a new decision");
  assert.equal(store.peek("github.com/other/pkg", "v1.7.2"), undefined);

  assert.notEqual(store.take("github.com/foo/bar", "v1.7.2"), undefined);
  assert.equal(store.take("github.com/foo/bar", "v1.7.2"), undefined, "consumed by one execution");
});

test("the pending set is bounded, and dropping one can only force a re-justification", () => {
  const store = createJustificationStore();
  for (let i = 0; i < 200; i += 1) {
    const parsed = parseJustification({ ...VALID, module: `example.com/m${i}` }, AT);
    if (parsed.ok) store.record(parsed.justification);
  }
  assert.ok(store.size() <= 64, `bounded, got ${store.size()}`);
  assert.equal(store.peek("example.com/m0", "v1.7.2"), undefined, "oldest dropped");
  assert.notEqual(store.peek("example.com/m199", "v1.7.2"), undefined, "newest kept");
});

// ---------------------------------------------------------------------------
// Arguments arrive from the model: a trust boundary
// ---------------------------------------------------------------------------

test("malformed tool arguments are rejected, never partially accepted", () => {
  for (const [label, args] of [
    ["not an object", "github.com/foo/bar"],
    ["an array", []],
    ["missing module", { ...VALID, module: undefined }],
    ["blank purpose", { ...VALID, purpose: "   " }],
    ["missing reason", { ...VALID, stdlibInsufficientReason: undefined }],
    ["non-boolean stdlibConsidered", { ...VALID, stdlibConsidered: "yes" }],
    ["overlong purpose", { ...VALID, purpose: "x".repeat(501) }],
  ] as const) {
    const parsed = parseJustification(args, AT);
    assert.equal(parsed.ok, false, label);
    if (!parsed.ok) assert.match(parsed.message, new RegExp(JUSTIFY_TOOL), label);
  }
});

test("a valid justification is normalized and timestamped", () => {
  const parsed = parseJustification({ ...VALID, purpose: "  padded  " }, AT);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;
  assert.equal(parsed.justification.purpose, "padded");
  assert.equal(parsed.justification.recordedAt, AT);
  assert.equal(parsed.justification.stdlibConsidered, true);
});

test("stdlibConsidered=false is recorded, not rejected", () => {
  const parsed = parseJustification(
    { ...VALID, stdlibConsidered: false, stdlibInsufficientReason: "not considered: vendor mandate" },
    AT,
  );
  assert.equal(parsed.ok, true);
  if (parsed.ok) assert.equal(parsed.justification.stdlibConsidered, false);
});

test("the parameter schema names every field the approval object needs", () => {
  assert.deepEqual(
    [...(JUSTIFY_TOOL_PARAMETERS.required as readonly string[])].sort(),
    ["module", "purpose", "stdlibConsidered", "stdlibInsufficientReason", "version"],
  );
  assert.equal(JUSTIFY_TOOL_PARAMETERS.additionalProperties, false);
});

// ---------------------------------------------------------------------------
// End to end through the runtime
// ---------------------------------------------------------------------------

interface Rec {
  readonly prompts: string[];
  answer: string | undefined;
}

async function runtimeAt(answer?: string): Promise<{
  runtime: SupplyGuardRuntime;
  ctx: never;
  rec: Rec;
  home: string;
  repo: string;
}> {
  const repo = await tempDir("supplyguard-just-repo-");
  const home = await tempDir("supplyguard-just-home-");
  await writeFile(join(repo, "go.mod"), "module m\n\ngo 1.22\n");
  const rec: Rec = { prompts: [], answer };
  const ctx = {
    cwd: repo,
    hasUI: true,
    mode: "tui" as const,
    ui: {
      select: async (title: string) => {
        rec.prompts.push(title);
        return rec.answer;
      },
      confirm: async () => false,
      input: async () => undefined,
      notify: () => {},
    },
    sessionManager: { getSessionId: () => "session-1" },
  };
  return { runtime: createRuntime({ home, env: {} }), ctx: ctx as never, rec, home, repo };
}

test("an unjustified dependency is denied before any human is asked", async () => {
  const h = await runtimeAt("Approve once");
  const blocked = await h.runtime.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "go get github.com/foo/bar@v1.7.2" } },
    h.ctx,
  );

  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /supplyguard_justify_dependency/);
  assert.deepEqual(h.rec.prompts, [], "a human is not asked to rubber-stamp an unexplained change");
});

test("a justified dependency reaches the human with the rationale attached", async () => {
  const h = await runtimeAt("Approve once");
  const recorded = await h.runtime.justifyTool(VALID, h.ctx);
  assert.notEqual(recorded.isError, true);

  const result = await h.runtime.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "go get github.com/foo/bar@v1.7.2" } },
    h.ctx,
  );

  assert.equal(result, undefined, "approved once");
  const prompt = h.rec.prompts.join("\n");
  assert.match(prompt, /Purpose\s+structured logging with levels/);
  assert.match(prompt, /Stdlib considered\s+yes/);
  assert.match(prompt, /Why not stdlib\s+log\/slog lacks the sink we need/);
});

// SECURITY: the agent supplies evidence, not consent (SPEC 17.1).
test("a justification is not an approval", async () => {
  const h = await runtimeAt("Deny");
  await h.runtime.justifyTool(VALID, h.ctx);

  const blocked = await h.runtime.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "go get github.com/foo/bar@v1.7.2" } },
    h.ctx,
  );
  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /Not approved by a human/);
});

// SPEC 11.3: "A version change is a new trust decision."
test("a justification does not carry to another version or a second run", async () => {
  const h = await runtimeAt("Approve once");
  await h.runtime.justifyTool(VALID, h.ctx);

  const other = await h.runtime.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "go get github.com/foo/bar@v1.7.3" } },
    h.ctx,
  );
  assert.equal(other?.block, true, "a different version is not covered");
  assert.match(other?.reason ?? "", /supplyguard_justify_dependency/);

  const first = await h.runtime.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "go get github.com/foo/bar@v1.7.2" } },
    h.ctx,
  );
  assert.equal(first, undefined, "the justified version goes through once");

  const second = await h.runtime.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "go get github.com/foo/bar@v1.7.2" } },
    h.ctx,
  );
  assert.equal(second?.block, true, "the justification was consumed by the first run");
});

test("a malformed tool call is an error the agent can correct, and records nothing", async () => {
  const h = await runtimeAt("Approve once");
  const result = await h.runtime.justifyTool({ module: "github.com/foo/bar" }, h.ctx);

  assert.equal(result.isError, true);
  assert.match(result.content[0]?.text ?? "", /"version" must be a non-empty string/);

  const blocked = await h.runtime.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "go get github.com/foo/bar@v1.7.2" } },
    h.ctx,
  );
  assert.equal(blocked?.block, true);
});

test("recording a justification is audited", async () => {
  const h = await runtimeAt("Approve once");
  await h.runtime.justifyTool(VALID, h.ctx);

  const log = await readFile(
    join(h.home, ".local", "state", "pi-supplyguard", "audit.jsonl"),
    "utf8",
  );
  const record = JSON.parse(log.trim().split("\n")[0] ?? "{}") as Record<string, unknown>;
  assert.equal(record["kind"], "justification");
  assert.equal(record["artifact"], "github.com/foo/bar");
  assert.equal(record["version"], "v1.7.2");
  assert.match(String(record["message"]), /structured logging with levels/);
});
