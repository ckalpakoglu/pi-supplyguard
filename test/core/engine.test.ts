/**
 * Engine pipeline, human approval gate and adapter registry (SPEC 5, 13.5, 17).
 *
 * These cover the security-critical path M1 exists to establish: an ASK must
 * reach a real human, a headless session must fail closed, external evidence
 * must be incapable of weakening a local decision, and a broken adapter or a
 * broken engine must never become a silent bypass.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { createAdapterRegistry, type EcosystemAdapter } from "../../src/adapters/registry.ts";
import { requestHumanApproval, APPROVE_ONCE, DENY } from "../../src/core/approval.ts";
import type { AuditRecord } from "../../src/core/audit.ts";
import { externalFinding } from "../../src/core/decisions.ts";
import { evaluateToolCall, type EngineContext } from "../../src/core/engine.ts";
import type {
  NormalizedToolCall,
  SupplyChainEvent,
  ToolCallClassification,
} from "../../src/core/events.ts";
import type { Profile } from "../../src/core/profiles.ts";

const CALL: NormalizedToolCall = { toolName: "bash", input: { command: "ls" } };

function event(over: Partial<SupplyChainEvent> = {}): SupplyChainEvent {
  return {
    eventClass: "DependencyAdd",
    ecosystem: "test",
    classification: "THIRD_PARTY_MUTATION",
    artifact: "example.com/pkg",
    version: "v1.0.0",
    summary: "adds a dependency",
    ...over,
  };
}

/** An adapter that reports a fixed classification and event set. */
function adapter(
  classification: ToolCallClassification,
  events: readonly SupplyChainEvent[] = [],
  id = "test",
): EcosystemAdapter {
  return { id, inspectToolCall: () => ({ classification, events }) };
}

interface Harness {
  readonly ctx: EngineContext;
  readonly audited: AuditRecord[];
  readonly prompts: string[];
}

/**
 * `answer` drives the fake UI: a string is what `select` returns, `"dismiss"`
 * models a dismissal/timeout (`select` resolves undefined) and `"throw"` models
 * a UI failure.
 */
function harness(
  options: {
    profile?: Profile;
    hasUI?: boolean;
    answer?: string | "dismiss" | "throw";
    adapters?: readonly EcosystemAdapter[];
    external?: EngineContext["externalEvidence"];
    auditEnabled?: boolean;
    auditFails?: boolean;
  } = {},
): Harness {
  const audited: AuditRecord[] = [];
  const prompts: string[] = [];
  const answer = options.answer ?? APPROVE_ONCE;

  const ctx: EngineContext = {
    repoRoot: "/repo",
    sessionId: "session-1",
    profile: options.profile ?? "standard",
    hasUI: options.hasUI ?? true,
    registry: createAdapterRegistry(options.adapters ?? []),
    ui: {
      hasUI: options.hasUI ?? true,
      select: async (title) => {
        prompts.push(title);
        if (answer === "throw") throw new Error("ui exploded");
        return answer === "dismiss" ? undefined : answer;
      },
    },
    audit: async (record) => {
      if (options.auditFails === true) throw new Error("disk full");
      audited.push(record);
    },
    auditEnabled: options.auditEnabled ?? true,
    now: () => new Date("2026-09-01T00:00:00.000Z"),
    ...(options.external === undefined ? {} : { externalEvidence: options.external }),
  };

  return { ctx, audited, prompts };
}

// BEHAVIOR: installing SupplyGuard must not tax ordinary development.
test("an irrelevant tool call is allowed, not prompted and not audited", async () => {
  const h = harness({ adapters: [adapter("SUPPLY_CHAIN_IRRELEVANT")] });
  const outcome = await evaluateToolCall(CALL, h.ctx);

  assert.equal(outcome.decision, "allow");
  assert.equal(outcome.blocked, false);
  assert.equal(outcome.audited, false);
  assert.deepEqual(h.audited, []);
  assert.deepEqual(h.prompts, []);
});

test("an empty registry produces no events, so every profile allows", async () => {
  for (const profile of ["standard", "hardened", "paranoid"] as const) {
    const h = harness({ profile });
    const outcome = await evaluateToolCall(CALL, h.ctx);
    assert.equal(outcome.decision, "allow", profile);
    assert.equal(outcome.blocked, false, profile);
  }
});

// SECURITY INVARIANT: an ASK routes to a real human (SPEC 17.1).
test("an ASK prompts a human and an approval allows the call once", async () => {
  const h = harness({
    adapters: [adapter("THIRD_PARTY_MUTATION", [event()])],
    answer: APPROVE_ONCE,
  });
  const outcome = await evaluateToolCall(CALL, h.ctx);

  assert.equal(outcome.decision, "allow");
  assert.equal(outcome.blocked, false);
  assert.equal(h.prompts.length, 1);
  assert.deepEqual(outcome.approval, {
    required: true,
    granted: true,
    reason: "approved-once",
  });
  assert.equal(h.audited.length, 1);
  assert.equal(h.audited[0]?.decision, "allow");
  assert.equal(h.audited[0]?.event, "DependencyAdd");
  assert.equal(h.audited[0]?.artifact, "example.com/pkg");
});

test("a human denial blocks the call", async () => {
  const h = harness({ adapters: [adapter("THIRD_PARTY_MUTATION", [event()])], answer: DENY });
  const outcome = await evaluateToolCall(CALL, h.ctx);

  assert.equal(outcome.decision, "deny");
  assert.equal(outcome.blocked, true);
  assert.equal(outcome.approval?.reason, "denied-by-human");
  assert.equal(h.audited[0]?.decision, "deny");
});

// SECURITY INVARIANT: silence is not consent.
test("a dismissed or timed-out prompt is not approval", async () => {
  const h = harness({
    adapters: [adapter("THIRD_PARTY_MUTATION", [event()])],
    answer: "dismiss",
  });
  const outcome = await evaluateToolCall(CALL, h.ctx);

  assert.equal(outcome.decision, "deny");
  assert.equal(outcome.approval?.reason, "no-response");
});

test("a UI failure is not approval", async () => {
  const h = harness({
    adapters: [adapter("THIRD_PARTY_MUTATION", [event()])],
    answer: "throw",
  });
  const outcome = await evaluateToolCall(CALL, h.ctx);

  assert.equal(outcome.decision, "deny");
  assert.equal(outcome.approval?.reason, "ui-error");
});

// SECURITY INVARIANT: headless fails closed and leaves evidence.
test("a headless ASK is never auto-approved and is audited with the reason", async () => {
  const h = harness({
    adapters: [adapter("THIRD_PARTY_MUTATION", [event()])],
    hasUI: false,
  });
  const outcome = await evaluateToolCall(CALL, h.ctx);

  assert.equal(outcome.decision, "deny");
  assert.equal(outcome.blocked, true);
  assert.deepEqual(h.prompts, [], "a headless session must not be prompted");
  assert.equal(outcome.approval?.reason, "headless-fail-closed");
  assert.equal(h.audited[0]?.headless, true);
  assert.equal(h.audited[0]?.decision, "deny");
});

// SECURITY INVARIANT: external intelligence is additive only (SPEC 13.5).
test("a clean external result cannot turn a local ASK into ALLOW", async () => {
  const h = harness({
    adapters: [adapter("THIRD_PARTY_MUTATION", [event()])],
    hasUI: false,
    external: async () => [externalFinding("test-provider", "clean", "allow", "clean")],
  });
  const outcome = await evaluateToolCall(CALL, h.ctx);

  // Local baseline said ask; headless resolved it to deny. A clean provider
  // result changed nothing.
  assert.equal(outcome.decision, "deny");
});

test("an external DENY tightens an otherwise-allowed call", async () => {
  const h = harness({
    adapters: [
      adapter("THIRD_PARTY_CAPABLE", [
        event({ eventClass: "DependencyFetch", classification: "THIRD_PARTY_CAPABLE" }),
      ]),
    ],
    external: async () => [
      externalFinding("test-provider", "malware", "deny", "known malicious"),
    ],
  });
  const outcome = await evaluateToolCall(CALL, h.ctx);

  assert.equal(outcome.decision, "deny");
  assert.equal(outcome.blocked, true);
});

test("a failing external provider warns but leaves local policy authoritative", async () => {
  const h = harness({
    adapters: [
      adapter("THIRD_PARTY_CAPABLE", [
        event({ eventClass: "DependencyFetch", classification: "THIRD_PARTY_CAPABLE" }),
      ]),
    ],
    external: async () => {
      throw new Error("provider timeout");
    },
  });
  const outcome = await evaluateToolCall(CALL, h.ctx);

  assert.equal(outcome.decision, "warn");
  assert.equal(outcome.blocked, false);
  assert.equal(outcome.warnings.length, 1);
});

// SECURITY INVARIANT: a broken adapter is not "nothing to see here".
test("an adapter that throws is treated as unknown risk, not as clean", async () => {
  const broken: EcosystemAdapter = {
    id: "broken",
    inspectToolCall: () => {
      throw new Error("parser crashed");
    },
  };

  const standard = await evaluateToolCall(CALL, harness({ adapters: [broken] }).ctx);
  assert.equal(standard.classification, "UNKNOWN_RISK");
  assert.equal(standard.decision, "allow", "approved once by the human harness");

  const paranoid = await evaluateToolCall(
    CALL,
    harness({ adapters: [broken], profile: "paranoid" }).ctx,
  ).then((o) => o);
  assert.equal(paranoid.decision, "deny", "paranoid denies unknown risk outright");
  assert.equal(paranoid.blocked, true);
});

// SECURITY INVARIANT: a SupplyGuard bug must not become a policy bypass.
test("an internal engine failure fails closed", async () => {
  const h = harness();
  const broken: EngineContext = {
    ...h.ctx,
    registry: {
      register: () => {},
      list: () => [],
      size: () => 0,
      sensitivePaths: () => [],
      inspectFileMutations: async () => ({ events: [], errors: [], notes: [] }),
      inspectProjectState: async () => ({ events: [], errors: [], notes: [] }),
      projectDecisions: async () => [],
      describe: async () => [],
      inspectToolCall: async () => {
        throw new Error("registry exploded");
      },
    },
  };

  const outcome = await evaluateToolCall(CALL, broken);
  assert.equal(outcome.decision, "deny");
  assert.equal(outcome.blocked, true);
  assert.match(outcome.reason, /failing closed/);
});

// An audit failure must be visible but must never change the decision.
test("an audit write failure does not weaken the decision", async () => {
  const h = harness({
    adapters: [adapter("THIRD_PARTY_MUTATION", [event()])],
    answer: DENY,
    auditFails: true,
  });
  const outcome = await evaluateToolCall(CALL, h.ctx);

  assert.equal(outcome.decision, "deny");
  assert.equal(outcome.blocked, true);
  assert.equal(outcome.audited, false);
  assert.equal(outcome.warnings.length, 1);
});

test("the most severe classification across adapters wins", async () => {
  const h = harness({
    adapters: [
      adapter("SUPPLY_CHAIN_IRRELEVANT", [], "quiet"),
      adapter("THIRD_PARTY_MUTATION", [event()], "loud"),
    ],
  });
  const outcome = await evaluateToolCall(CALL, h.ctx);
  assert.equal(outcome.classification, "THIRD_PARTY_MUTATION");
});

test("duplicate adapter ids are rejected", () => {
  const registry = createAdapterRegistry([adapter("SUPPLY_CHAIN_IRRELEVANT", [], "go")]);
  assert.throws(
    () => registry.register(adapter("SUPPLY_CHAIN_IRRELEVANT", [], "go")),
    /duplicate ecosystem adapter/,
  );
  assert.equal(registry.size(), 1);
});

// Approval gate in isolation: no grant is ever produced without a human answer.
test("requestHumanApproval never approves without an explicit human answer", async () => {
  const ui = {
    hasUI: false,
    select: async () => APPROVE_ONCE,
  };
  const result = await requestHumanApproval(
    { title: "t", lines: [], profile: "paranoid" },
    ui,
  );

  assert.equal(result.grant.approved, false);
  assert.equal(result.headless, true);
  assert.equal(result.reason, "headless-fail-closed");
});
