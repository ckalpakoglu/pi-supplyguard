import assert from "node:assert/strict";
import { test } from "node:test";

import { decisionRank, isDecision } from "../../src/core/decisions.ts";
import {
  SUPPLY_CHAIN_EVENT_CLASSES,
  TOOL_CALL_CLASSIFICATIONS,
} from "../../src/core/events.ts";
import {
  baselineForClassification,
  baselineForEvent,
  CLASSIFICATION_BASELINE,
  DEFAULT_PROFILE,
  effectiveProfile,
  EVENT_BASELINE,
  isProfile,
  maxProfile,
  parseProfile,
  profileRank,
  PROFILES,
} from "../../src/core/profiles.ts";

test("standard is the default profile", () => {
  assert.equal(DEFAULT_PROFILE, "standard");
});

test("profile ordering is standard < hardened < paranoid", () => {
  assert.deepEqual([...PROFILES], ["standard", "hardened", "paranoid"]);
  assert.ok(profileRank("standard") < profileRank("hardened"));
  assert.ok(profileRank("hardened") < profileRank("paranoid"));
});

test("parseProfile rejects untrusted values", () => {
  assert.equal(parseProfile("paranoid"), "paranoid");
  assert.equal(parseProfile("Paranoid"), undefined);
  assert.equal(parseProfile("off"), undefined);
  assert.equal(parseProfile(3), undefined);
  assert.ok(isProfile("hardened"));
  assert.ok(!isProfile("hardened "));
});

test("maxProfile with no arguments falls back to the default", () => {
  assert.equal(maxProfile(), "standard");
});

// SECURITY INVARIANT: effectiveProfile = max(global, project) (SPEC 4).
test("a project profile may tighten the global baseline (positive case)", () => {
  assert.equal(effectiveProfile("standard", "hardened"), "hardened");
  assert.equal(effectiveProfile("standard", "paranoid"), "paranoid");
  assert.equal(effectiveProfile("hardened", "paranoid"), "paranoid");
});

test("a project profile may never weaken the global baseline (negative case)", () => {
  assert.equal(effectiveProfile("paranoid", "standard"), "paranoid");
  assert.equal(effectiveProfile("paranoid", "hardened"), "paranoid");
  assert.equal(effectiveProfile("hardened", "standard"), "hardened");
});

test("effectiveProfile without a project profile keeps the global one", () => {
  for (const profile of PROFILES) {
    assert.equal(effectiveProfile(profile), profile);
  }
});

test("every event class and classification has a decision for every profile", () => {
  for (const eventClass of SUPPLY_CHAIN_EVENT_CLASSES) {
    for (const profile of PROFILES) {
      const decision = EVENT_BASELINE[eventClass][profile];
      assert.ok(isDecision(decision), `${eventClass}/${profile}`);
    }
  }
  for (const classification of TOOL_CALL_CLASSIFICATIONS) {
    for (const profile of PROFILES) {
      assert.ok(isDecision(CLASSIFICATION_BASELINE[classification][profile]));
    }
  }
});

test("baselines never become less restrictive as the profile tightens", () => {
  for (const eventClass of SUPPLY_CHAIN_EVENT_CLASSES) {
    const [standard, hardened, paranoid] = [
      baselineForEvent(eventClass, "standard"),
      baselineForEvent(eventClass, "hardened"),
      baselineForEvent(eventClass, "paranoid"),
    ];
    assert.ok(decisionRank(hardened) >= decisionRank(standard), `${eventClass} hardened`);
    assert.ok(decisionRank(paranoid) >= decisionRank(hardened), `${eventClass} paranoid`);
  }
  for (const classification of TOOL_CALL_CLASSIFICATIONS) {
    const standard = baselineForClassification(classification, "standard");
    const hardened = baselineForClassification(classification, "hardened");
    const paranoid = baselineForClassification(classification, "paranoid");
    assert.ok(decisionRank(hardened) >= decisionRank(standard), `${classification} hardened`);
    assert.ok(decisionRank(paranoid) >= decisionRank(hardened), `${classification} paranoid`);
  }
});

// Contract table (SPEC 4.4), ecosystem-agnostic subset enforced in M1.
test("profile x event decision contract table", () => {
  const expected: Record<string, [string, string, string]> = {
    DependencyAdd: ["ask", "ask", "ask"],
    DependencyUpgrade: ["ask", "ask", "ask"],
    DependencyDowngrade: ["ask", "ask", "ask"],
    DependencyReplace: ["ask", "ask", "ask"],
    DependencyRemove: ["warn", "warn", "warn"],
    ToolInstall: ["ask", "ask", "ask"],
    ToolUpgrade: ["ask", "ask", "ask"],
    ThirdPartyExecution: ["ask", "ask", "ask"],
    LockfileMutation: ["ask", "ask", "ask"],
    VendorDrift: ["warn", "deny", "deny"],
    ChecksumBypass: ["deny", "deny", "deny"],
    SecurityBypass: ["deny", "deny", "deny"],
    SecurityGateChange: ["ask", "deny", "deny"],
    CIReferenceAdd: ["ask", "ask", "ask"],
    CIReferenceChange: ["ask", "ask", "ask"],
    NetworkRequirement: ["allow", "ask", "deny"],
    RegistryAccess: ["allow", "warn", "ask"],
    DependencyFetch: ["allow", "warn", "ask"],
  };

  assert.equal(
    Object.keys(expected).length,
    SUPPLY_CHAIN_EVENT_CLASSES.length,
    "the contract table must cover every canonical event class",
  );

  for (const eventClass of SUPPLY_CHAIN_EVENT_CLASSES) {
    const row = expected[eventClass];
    assert.ok(row !== undefined, `missing contract row for ${eventClass}`);
    assert.deepEqual(
      [
        baselineForEvent(eventClass, "standard"),
        baselineForEvent(eventClass, "hardened"),
        baselineForEvent(eventClass, "paranoid"),
      ],
      row,
      eventClass,
    );
  }
});

test("profile x classification decision contract table", () => {
  assert.deepEqual(
    TOOL_CALL_CLASSIFICATIONS.map((c) => [
      c,
      baselineForClassification(c, "standard"),
      baselineForClassification(c, "hardened"),
      baselineForClassification(c, "paranoid"),
    ]),
    [
      ["SUPPLY_CHAIN_IRRELEVANT", "allow", "allow", "allow"],
      ["THIRD_PARTY_CAPABLE", "allow", "allow", "warn"],
      ["THIRD_PARTY_MUTATION", "ask", "ask", "ask"],
      ["UNKNOWN_RISK", "ask", "ask", "deny"],
    ],
  );
});

// BEHAVIORAL INVARIANT: installing SupplyGuard must not tax ordinary work.
test("supply-chain-irrelevant work is allowed in every profile", () => {
  for (const profile of PROFILES) {
    assert.equal(baselineForClassification("SUPPLY_CHAIN_IRRELEVANT", profile), "allow");
  }
});

// SECURITY INVARIANT: unknown operations fail conservatively (SPEC 5.1).
test("unknown risk is never allowed", () => {
  for (const profile of PROFILES) {
    assert.notEqual(baselineForClassification("UNKNOWN_RISK", profile), "allow");
  }
});
