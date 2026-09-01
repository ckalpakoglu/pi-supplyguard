/**
 * The Go adapter through the real engine (SPEC 4.4, 7, 23.3).
 *
 * These exercise the whole path — adapter, normalized events, profile
 * baselines, adapter-asserted floors, human gate, audit — rather than the
 * command parser alone.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { createGoAdapter } from "../../src/adapters/go/index.ts";
import { createAdapterRegistry } from "../../src/adapters/registry.ts";
import { APPROVE_ONCE } from "../../src/core/approval.ts";
import type { AuditRecord } from "../../src/core/audit.ts";
import { evaluateToolCall, type EngineContext } from "../../src/core/engine.ts";
import type { Profile } from "../../src/core/profiles.ts";

interface Harness {
  readonly ctx: EngineContext;
  readonly audited: AuditRecord[];
  readonly prompts: string[];
}

function harness(options: { profile?: Profile; hasUI?: boolean; answer?: string } = {}): Harness {
  const audited: AuditRecord[] = [];
  const prompts: string[] = [];
  const hasUI = options.hasUI ?? true;

  return {
    audited,
    prompts,
    ctx: {
      repoRoot: "/repo",
      sessionId: "session-1",
      profile: options.profile ?? "standard",
      hasUI,
      registry: createAdapterRegistry([createGoAdapter()]),
      ui: {
        hasUI,
        select: async (title: string) => {
          prompts.push(title);
          return options.answer ?? APPROVE_ONCE;
        },
      },
      audit: async (record) => {
        audited.push(record);
      },
      auditEnabled: true,
      now: () => new Date("2026-09-01T00:00:00.000Z"),
    },
  };
}

function bash(command: string) {
  return { toolName: "bash", input: { command } };
}

// ---------------------------------------------------------------------------
// The decision table, end to end.
// ---------------------------------------------------------------------------

test("a floating version is denied in every profile, human present or not", async () => {
  for (const profile of ["standard", "hardened", "paranoid"] as const) {
    const h = harness({ profile, answer: APPROVE_ONCE });
    const outcome = await evaluateToolCall(bash("go get github.com/foo/bar@latest"), h.ctx);

    assert.equal(outcome.decision, "deny", profile);
    assert.equal(outcome.blocked, true, profile);
    // A DENY is not negotiable: no approval prompt is offered for it.
    assert.deepEqual(h.prompts, [], `${profile} must not offer to approve a denial`);
  }
});

test("GOSUMDB=off is denied in every profile — invariant 18", async () => {
  for (const profile of ["standard", "hardened", "paranoid"] as const) {
    const h = harness({ profile });
    const outcome = await evaluateToolCall(bash("GOSUMDB=off go test ./..."), h.ctx);
    assert.equal(outcome.decision, "deny", profile);
    assert.equal(h.audited[0]?.event, "ChecksumBypass", profile);
  }
});

// NEGATIVE CASE: a pinned dependency is a normal trust decision, not a wall.
test("an exact version asks a human and proceeds on approval", async () => {
  const h = harness({ answer: APPROVE_ONCE });
  const outcome = await evaluateToolCall(bash("go get github.com/foo/bar@v1.7.2"), h.ctx);

  assert.equal(outcome.decision, "allow");
  assert.equal(outcome.blocked, false);
  assert.equal(h.prompts.length, 1);
  assert.match(h.prompts[0] ?? "", /github\.com\/foo\/bar/);
  assert.equal(h.audited[0]?.artifact, "github.com/foo/bar");
  assert.equal(h.audited[0]?.version, "v1.7.2");
  assert.equal(h.audited[0]?.ecosystem, "go");
});

test("a human denial of a pinned dependency blocks it", async () => {
  const h = harness({ answer: "Deny" });
  const outcome = await evaluateToolCall(bash("go get github.com/foo/bar@v1.7.2"), h.ctx);
  assert.equal(outcome.decision, "deny");
});

// ---------------------------------------------------------------------------
// DELEGATION: Chief-only dependency mutations (human decision, 2026-09-01).
// ---------------------------------------------------------------------------

test("a delegated headless worker cannot add a dependency, even a pinned one", async () => {
  const h = harness({ hasUI: false });
  const outcome = await evaluateToolCall(bash("go get github.com/foo/bar@v1.7.2"), h.ctx);

  assert.equal(outcome.decision, "deny");
  assert.equal(outcome.blocked, true);
  assert.deepEqual(h.prompts, [], "there is no human to ask in a worker session");
  assert.equal(outcome.approval?.reason, "headless-fail-closed");
  // The audit record is the evidence the Chief needs to perform it instead.
  assert.equal(h.audited[0]?.headless, true);
  assert.equal(h.audited[0]?.event, "DependencyAdd");
  assert.equal(h.audited[0]?.artifact, "github.com/foo/bar");
});

// NEGATIVE CASE: a worker must still be able to do ordinary work.
test("a headless worker can still build and test", async () => {
  const h = harness({ hasUI: false });
  for (const command of ["go build ./...", "go test ./...", "gofmt -w .", "git status"]) {
    const outcome = await evaluateToolCall(bash(command), h.ctx);
    assert.equal(outcome.decision, "allow", command);
    assert.equal(outcome.blocked, false, command);
  }
});

// ---------------------------------------------------------------------------
// Profile differences must be real, not just louder warnings (SPEC 1.1).
// ---------------------------------------------------------------------------

test("paranoid denies an unreadable command that standard merely gates", async () => {
  // An unrecognized wrapper: unknown risk, but nothing the adapter can assert
  // a floor for. SPEC 5.1 wants this to fail conservative BY PROFILE.
  const command = "weirdwrapper go get github.com/foo/bar@v1.7.2";

  const standard = await evaluateToolCall(bash(command), harness({ profile: "standard" }).ctx);
  assert.equal(standard.classification, "UNKNOWN_RISK");
  assert.equal(standard.decision, "allow", "asked, and approved by this harness");

  const paranoid = await evaluateToolCall(bash(command), harness({ profile: "paranoid" }).ctx);
  assert.equal(paranoid.decision, "deny", "paranoid does not offer the choice");
  assert.equal(paranoid.blocked, true);
});

// A version that cannot be proven exact is denied outright, whatever the
// profile -- there is no version to approve.
test("a version behind a command substitution is denied, not merely gated", async () => {
  const outcome = await evaluateToolCall(bash("go get $(cat version.txt)"), harness().ctx);
  assert.equal(outcome.decision, "deny");
});

// ---------------------------------------------------------------------------
// SupplyGuard must not tax ordinary development (SPEC 2.2, 5.1).
// ---------------------------------------------------------------------------

test("harmless tool calls are allowed, unprompted and unaudited", async () => {
  const h = harness();
  for (const command of ["ls -la", "git status", "gofmt -l .", "cat README.md", "go version"]) {
    const outcome = await evaluateToolCall(bash(command), h.ctx);
    assert.equal(outcome.decision, "allow", command);
    assert.equal(outcome.audited, false, `${command} must not be audited`);
  }
  assert.deepEqual(h.prompts, []);
  assert.deepEqual(h.audited, []);
});

test("a tool call with no command field is not the Go adapter's business", async () => {
  const h = harness();
  const outcome = await evaluateToolCall(
    { toolName: "read_file", input: { path: "/repo/main.go" } },
    h.ctx,
  );
  assert.equal(outcome.decision, "allow");
  assert.equal(outcome.audited, false);
});

// ---------------------------------------------------------------------------
// The adapter-asserted floor may only tighten (SPEC 6.1).
// ---------------------------------------------------------------------------

test("an adapter floor tightens a baseline but never loosens one", async () => {
  // No adapter floor: the profile baseline decides, so a human is asked and
  // the approval stands.
  const h = harness({ answer: APPROVE_ONCE });
  const remove = await evaluateToolCall(bash("go get github.com/foo/bar@none"), h.ctx);
  assert.equal(remove.decision, "allow");
  assert.equal(remove.approval?.granted, true);
  assert.equal(h.audited[0]?.event, "DependencyRemove");

  // A deny floor overrides the same approving human: a floating version is not
  // an approvable trust decision, it is an invariant violation.
  const approving = harness({ answer: APPROVE_ONCE });
  const floating = await evaluateToolCall(
    bash("go get github.com/foo/bar@some-branch"),
    approving.ctx,
  );
  assert.equal(floating.decision, "deny");
  assert.deepEqual(approving.prompts, [], "a denial is never offered for approval");
});
