/**
 * Security profiles (SPEC 4).
 *
 *     standard < hardened < paranoid
 *     effectiveProfile = max(globalProfile, projectProfile)
 *
 * A project may tighten the global baseline but may never silently weaken it.
 *
 * This module also holds the ecosystem-agnostic baseline policy tables derived
 * from the SPEC 4.4 matrix. Later milestones add analyzers (release age,
 * identity, vulnerability, external providers) whose findings are folded in
 * through `src/core/decisions.ts`, which can only tighten these baselines.
 */

import type { Decision } from "./decisions.ts";
import type { SupplyChainEventClass, ToolCallClassification } from "./events.ts";

export const PROFILES = ["standard", "hardened", "paranoid"] as const;

export type Profile = (typeof PROFILES)[number];

/** SPEC 1.1 / 27.2 -- `standard` is the default profile. */
export const DEFAULT_PROFILE: Profile = "standard";

const PROFILE_RANK = {
  standard: 0,
  hardened: 1,
  paranoid: 2,
} as const satisfies Record<Profile, number>;

/** Higher rank means stricter. */
export function profileRank(profile: Profile): number {
  return PROFILE_RANK[profile];
}

export function isProfile(value: unknown): value is Profile {
  return typeof value === "string" && (PROFILES as readonly string[]).includes(value);
}

/** Parse an untrusted value, e.g. from a configuration file. */
export function parseProfile(value: unknown): Profile | undefined {
  return isProfile(value) ? value : undefined;
}

/** Combine profiles; the strictest wins. With no arguments: the default. */
export function maxProfile(...profiles: readonly Profile[]): Profile {
  let winner: Profile = DEFAULT_PROFILE;
  for (const profile of profiles) {
    if (profileRank(profile) > profileRank(winner)) winner = profile;
  }
  return winner;
}

/**
 * SPEC 4: `effectiveProfile = max(globalProfile, projectProfile)`.
 *
 * Passing a weaker project profile is not an error -- it is simply ignored,
 * which is exactly the "may tighten, may not weaken" rule.
 */
export function effectiveProfile(
  globalProfile: Profile,
  projectProfile?: Profile,
): Profile {
  return projectProfile === undefined
    ? globalProfile
    : maxProfile(globalProfile, projectProfile);
}

export type ProfileDecisionRow = Readonly<Record<Profile, Decision>>;

/**
 * Baseline decision per normalized event class and profile.
 *
 * Derived from SPEC 4.4. These are event-shape baselines only: refinement
 * (exact-version rules, mutability of a CI reference, release age, provider
 * evidence, ...) belongs to later milestones and may only tighten the result.
 */
export const EVENT_BASELINE = {
  // New or changed third-party trust -> human trust decision in every profile.
  DependencyAdd: { standard: "ask", hardened: "ask", paranoid: "ask" },
  DependencyUpgrade: { standard: "ask", hardened: "ask", paranoid: "ask" },
  DependencyDowngrade: { standard: "ask", hardened: "ask", paranoid: "ask" },
  DependencyReplace: { standard: "ask", hardened: "ask", paranoid: "ask" },
  ToolInstall: { standard: "ask", hardened: "ask", paranoid: "ask" },
  ToolUpgrade: { standard: "ask", hardened: "ask", paranoid: "ask" },
  // SPEC 13.7: download-and-execute is at least as strict as an addition.
  ThirdPartyExecution: { standard: "ask", hardened: "ask", paranoid: "ask" },
  LockfileMutation: { standard: "ask", hardened: "ask", paranoid: "ask" },
  // Removal reduces third-party surface; it is recorded, not gated.
  DependencyRemove: { standard: "warn", hardened: "warn", paranoid: "warn" },
  // SPEC 4.4 "Vendor drift": Warn / Deny completion / Deny completion.
  VendorDrift: { standard: "warn", hardened: "deny", paranoid: "deny" },
  // Integrity-control bypass is an invariant violation in every profile.
  ChecksumBypass: { standard: "deny", hardened: "deny", paranoid: "deny" },
  SecurityBypass: { standard: "deny", hardened: "deny", paranoid: "deny" },
  // Weakening a security gate is a trust decision, and a gate in stricter
  // profiles.
  SecurityGateChange: { standard: "ask", hardened: "deny", paranoid: "deny" },
  // CI supply-chain references are trust decisions.
  CIReferenceAdd: { standard: "ask", hardened: "ask", paranoid: "ask" },
  CIReferenceChange: { standard: "ask", hardened: "ask", paranoid: "ask" },
  // Network/fetch shaped events. SPEC 4.4 "Build network":
  // Allowed/audited | Ask/audit | Deny by default.
  NetworkRequirement: { standard: "allow", hardened: "ask", paranoid: "deny" },
  RegistryAccess: { standard: "allow", hardened: "warn", paranoid: "ask" },
  DependencyFetch: { standard: "allow", hardened: "warn", paranoid: "ask" },
} as const satisfies Record<SupplyChainEventClass, ProfileDecisionRow>;

/**
 * Baseline decision per tool-call classification and profile (SPEC 5.1).
 *
 * `SUPPLY_CHAIN_IRRELEVANT` must stay `allow` in every profile: installing
 * SupplyGuard may not degrade ordinary development.
 */
export const CLASSIFICATION_BASELINE = {
  SUPPLY_CHAIN_IRRELEVANT: { standard: "allow", hardened: "allow", paranoid: "allow" },
  THIRD_PARTY_CAPABLE: { standard: "allow", hardened: "allow", paranoid: "warn" },
  THIRD_PARTY_MUTATION: { standard: "ask", hardened: "ask", paranoid: "ask" },
  // Fail conservative on unrecognized package/network-capable operations.
  UNKNOWN_RISK: { standard: "ask", hardened: "ask", paranoid: "deny" },
} as const satisfies Record<ToolCallClassification, ProfileDecisionRow>;

export function baselineForEvent(
  eventClass: SupplyChainEventClass,
  profile: Profile,
): Decision {
  return EVENT_BASELINE[eventClass][profile];
}

export function baselineForClassification(
  classification: ToolCallClassification,
  profile: Profile,
): Decision {
  return CLASSIFICATION_BASELINE[classification][profile];
}
