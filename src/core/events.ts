/**
 * Normalized, ecosystem-independent event model (SPEC 5.1, 6).
 *
 * Adapters translate ecosystem-specific commands, manifests and project state
 * into these shapes. The core never learns what a package manager is.
 */

import type { Decision } from "./decisions.ts";

/** SPEC 6 -- canonical event classes. */
export const SUPPLY_CHAIN_EVENT_CLASSES = [
  "DependencyAdd",
  "DependencyUpgrade",
  "DependencyDowngrade",
  "DependencyRemove",
  "DependencyReplace",
  "ToolInstall",
  "ToolUpgrade",
  "ThirdPartyExecution",
  "LockfileMutation",
  "VendorDrift",
  "ChecksumBypass",
  "RegistryAccess",
  "DependencyFetch",
  "ArtifactAnomaly",
  "CIReferenceAdd",
  "CIReferenceChange",
  "NetworkRequirement",
  "SecurityGateChange",
  "SecurityBypass",
] as const;

export type SupplyChainEventClass = (typeof SUPPLY_CHAIN_EVENT_CLASSES)[number];

export function isSupplyChainEventClass(value: unknown): value is SupplyChainEventClass {
  return (
    typeof value === "string" &&
    (SUPPLY_CHAIN_EVENT_CLASSES as readonly string[]).includes(value)
  );
}

/** SPEC 5.1 -- every tool call is classified before anything else happens. */
export const TOOL_CALL_CLASSIFICATIONS = [
  "SUPPLY_CHAIN_IRRELEVANT",
  "THIRD_PARTY_CAPABLE",
  "THIRD_PARTY_MUTATION",
  "UNKNOWN_RISK",
] as const;

export type ToolCallClassification = (typeof TOOL_CALL_CLASSIFICATIONS)[number];

/**
 * Classification severity ordering.
 *
 * `UNKNOWN_RISK` ranks highest because an unrecognized operation that can
 * mutate package or network trust must fail conservatively (SPEC 5.1).
 */
const CLASSIFICATION_RANK = {
  SUPPLY_CHAIN_IRRELEVANT: 0,
  THIRD_PARTY_CAPABLE: 1,
  THIRD_PARTY_MUTATION: 2,
  UNKNOWN_RISK: 3,
} as const satisfies Record<ToolCallClassification, number>;

export function classificationRank(classification: ToolCallClassification): number {
  return CLASSIFICATION_RANK[classification];
}

/** Combine classifications; the most severe wins. Identity is irrelevant. */
export function mostSevereClassification(
  ...classifications: readonly ToolCallClassification[]
): ToolCallClassification {
  let winner: ToolCallClassification = "SUPPLY_CHAIN_IRRELEVANT";
  for (const classification of classifications) {
    if (classificationRank(classification) > classificationRank(winner)) {
      winner = classification;
    }
  }
  return winner;
}

/**
 * A Pi tool call, normalized for the core.
 *
 * `input` is a read-only view. The core deliberately never writes to tool
 * input: rewriting a tool call is a documented bypass vector (see
 * `src/index.ts`), not a SupplyGuard enforcement mechanism.
 */
export interface NormalizedToolCall {
  readonly toolName: string;
  readonly toolCallId?: string;
  readonly input: Readonly<Record<string, unknown>>;
}

/** Metadata values allowed in events and audit records. Never secrets. */
export type EventDetailValue = string | number | boolean;

/**
 * A normalized supply-chain event produced by an ecosystem adapter.
 *
 * `ecosystem` is an opaque adapter id to the core. The engine must not branch
 * on its value.
 */
export interface SupplyChainEvent {
  /**
   * A floor the adapter asserts for this event, independent of profile.
   *
   * Some rules are invariants rather than profile preferences: a floating
   * version or a checksum bypass is denied in every profile (SPEC 4.4, 10.2,
   * 10.3). An adapter states that here; the engine folds it in with
   * `mostRestrictive`, so it can only ever TIGHTEN the profile baseline and
   * can never weaken it. The engine still learns nothing about the ecosystem
   * -- it sees a decision, not a reason.
   */
  readonly minimumDecision?: Decision;
  readonly eventClass: SupplyChainEventClass;
  readonly ecosystem: string;
  readonly classification: ToolCallClassification;
  /** Package/module/tool identity, when the event has one. */
  readonly artifact?: string;
  /** Exact version, when the event has one. */
  readonly version?: string;
  /** Short human-readable summary. Never a secret. */
  readonly summary: string;
  readonly detail?: Readonly<Record<string, EventDetailValue>>;
}
