import assert from "node:assert/strict";
import { test } from "node:test";

import {
  addLocalFindings,
  applyHumanApproval,
  DECISIONS,
  decisionRank,
  decisiveFindings,
  evaluateLocal,
  explain,
  externalFinding,
  isAtLeastAsRestrictiveAs,
  isDecision,
  localFinding,
  mostRestrictive,
  withExternalEvidence,
  type Decision,
  type HumanApprovalGrant,
} from "../../src/core/decisions.ts";

const GRANT_AT = "2026-09-01T00:00:00.000Z";

function grant(approved: boolean): HumanApprovalGrant {
  return {
    verifiedBy: "human-ui",
    approved,
    reason: approved ? "approved-once" : "denied-by-human",
    at: GRANT_AT,
  };
}

test("decision ordering is ALLOW < WARN < ASK < DENY", () => {
  assert.deepEqual([...DECISIONS], ["allow", "warn", "ask", "deny"]);
  const ranks = DECISIONS.map(decisionRank);
  assert.deepEqual(ranks, [0, 1, 2, 3]);
  for (let i = 1; i < ranks.length; i += 1) {
    assert.ok((ranks[i] ?? 0) > (ranks[i - 1] ?? 0), "ranks must be strictly increasing");
  }
});

test("isDecision accepts decisions and rejects anything else", () => {
  assert.ok(isDecision("deny"));
  assert.ok(!isDecision("DENY"));
  assert.ok(!isDecision("approve"));
  assert.ok(!isDecision(undefined));
});

test("mostRestrictive wins for every ordered pair, in both argument orders", () => {
  for (const a of DECISIONS) {
    for (const b of DECISIONS) {
      const expected: Decision = decisionRank(a) >= decisionRank(b) ? a : b;
      assert.equal(mostRestrictive(a, b), expected);
      assert.equal(mostRestrictive(b, a), expected);
    }
  }
});

test("mostRestrictive with no decisions is allow (identity element)", () => {
  assert.equal(mostRestrictive(), "allow");
});

test("isAtLeastAsRestrictiveAs", () => {
  assert.ok(isAtLeastAsRestrictiveAs("deny", "ask"));
  assert.ok(isAtLeastAsRestrictiveAs("ask", "ask"));
  assert.ok(!isAtLeastAsRestrictiveAs("warn", "ask"));
});

test("evaluateLocal takes the most restrictive finding", () => {
  const evaluation = evaluateLocal([
    localFinding("a", "x", "allow", "fine"),
    localFinding("b", "y", "ask", "gate"),
    localFinding("c", "z", "warn", "noted"),
  ]);
  assert.equal(evaluation.decision, "ask");
  assert.equal(evaluation.findings.length, 3);
  assert.deepEqual(
    decisiveFindings(evaluation).map((f) => f.code),
    ["y"],
  );
});

test("evaluateLocal with no findings allows", () => {
  assert.equal(evaluateLocal([]).decision, "allow");
});

test("addLocalFindings can tighten", () => {
  const base = evaluateLocal([localFinding("a", "x", "warn", "noted")]);
  const next = addLocalFindings(base, [localFinding("b", "y", "deny", "blocked")]);
  assert.equal(next.decision, "deny");
});

test("addLocalFindings cannot weaken (negative case)", () => {
  const base = evaluateLocal([localFinding("a", "x", "deny", "blocked")]);
  const next = addLocalFindings(base, [localFinding("b", "y", "allow", "looks fine")]);
  assert.equal(next.decision, "deny");
});

// SECURITY INVARIANT: external intelligence is additive only (SPEC 13.5).
test("external evidence may tighten a local decision (positive case)", () => {
  const base = evaluateLocal([localFinding("local", "baseline", "warn", "noted")]);
  const next = withExternalEvidence(base, [
    externalFinding("provider", "malware", "deny", "provider flagged the artifact"),
  ]);
  assert.equal(next.decision, "deny");
  assert.equal(next.findings.length, 2);
});

test("a clean external result can never weaken a local ask or deny (negative case)", () => {
  for (const local of ["ask", "deny"] as const) {
    const base = evaluateLocal([localFinding("local", "policy", local, "local policy")]);
    const next = withExternalEvidence(base, [
      externalFinding("provider", "clean", "allow", "provider says clean"),
      externalFinding("provider", "clean-2", "allow", "still clean"),
    ]);
    assert.equal(next.decision, local, `external evidence weakened a local ${local}`);
  }
});

test("external evidence is recorded even when it does not change the decision", () => {
  const base = evaluateLocal([localFinding("local", "policy", "deny", "local policy")]);
  const next = withExternalEvidence(base, [
    externalFinding("provider", "clean", "allow", "provider says clean"),
  ]);
  assert.equal(next.findings.length, 2);
  assert.equal(next.findings.filter((f) => f.origin === "external").length, 1);
});

// SECURITY INVARIANT: only a human grant resolves an ASK (SPEC 17.1).
test("human approval resolves ask to allow", () => {
  const base = evaluateLocal([localFinding("local", "new-dependency", "ask", "gate")]);
  const resolved = applyHumanApproval(base, grant(true));
  assert.equal(resolved.decision, "allow");
  assert.ok(resolved.findings.some((f) => f.origin === "human" && f.code === "approved-once"));
});

test("a refused ask becomes deny", () => {
  const base = evaluateLocal([localFinding("local", "new-dependency", "ask", "gate")]);
  const resolved = applyHumanApproval(base, grant(false));
  assert.equal(resolved.decision, "deny");
  assert.ok(resolved.findings.some((f) => f.origin === "human" && f.code === "not-approved"));
});

test("human approval cannot lower a deny (negative case)", () => {
  const base = evaluateLocal([localFinding("local", "invariant", "deny", "invariant violation")]);
  const resolved = applyHumanApproval(base, grant(true));
  assert.equal(resolved.decision, "deny");
  assert.equal(resolved.findings.length, base.findings.length);
});

test("human approval does not change allow or warn", () => {
  for (const decision of ["allow", "warn"] as const) {
    const base = evaluateLocal([localFinding("local", "x", decision, "m")]);
    assert.equal(applyHumanApproval(base, grant(true)).decision, decision);
    assert.equal(applyHumanApproval(base, grant(false)).decision, decision);
  }
});

test("explain reports the decisive findings", () => {
  const evaluation = evaluateLocal([
    localFinding("a", "x", "warn", "a warning"),
    localFinding("b", "y", "deny", "the blocking reason"),
  ]);
  assert.equal(explain(evaluation), "the blocking reason");
});
