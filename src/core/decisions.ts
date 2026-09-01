/**
 * Decision model (SPEC 6.1).
 *
 *     ALLOW < WARN < ASK < DENY
 *
 * The most restrictive decision always wins. This module is the ONLY place
 * where decisions are combined, and every combinator here is monotone: the
 * result can never be less restrictive than the base it was derived from.
 *
 * The single deliberate exception is `applyHumanApproval`, which may lower a
 * pending `ask` to `allow` -- and only when handed a grant that was produced by
 * a real human gate (`src/core/approval.ts`). It can never lower a `deny`.
 *
 * This file is ecosystem-agnostic. No package-manager knowledge belongs here.
 */

export const DECISIONS = ["allow", "warn", "ask", "deny"] as const;

export type Decision = (typeof DECISIONS)[number];

const DECISION_RANK = {
  allow: 0,
  warn: 1,
  ask: 2,
  deny: 3,
} as const satisfies Record<Decision, number>;

/** Higher rank means more restrictive. */
export function decisionRank(decision: Decision): number {
  return DECISION_RANK[decision];
}

export function isDecision(value: unknown): value is Decision {
  return typeof value === "string" && (DECISIONS as readonly string[]).includes(value);
}

/** `true` when `a` is at least as restrictive as `b`. */
export function isAtLeastAsRestrictiveAs(a: Decision, b: Decision): boolean {
  return decisionRank(a) >= decisionRank(b);
}

/**
 * Combine decisions. The most restrictive wins.
 *
 * With no arguments the result is `allow`: "nothing objected" is the identity
 * element, which is what makes the fold below safe.
 */
export function mostRestrictive(...decisions: readonly Decision[]): Decision {
  let winner: Decision = "allow";
  for (const decision of decisions) {
    if (decisionRank(decision) > decisionRank(winner)) {
      winner = decision;
    }
  }
  return winner;
}

export const FINDING_ORIGINS = ["local", "external", "human"] as const;

export type FindingOrigin = (typeof FINDING_ORIGINS)[number];

/**
 * A single reason contributing to a decision.
 *
 * `origin` is load-bearing: `external` findings come from third-party
 * intelligence providers and are additive only (SPEC 13.5). They enter an
 * evaluation exclusively through `withExternalEvidence`, which cannot lower a
 * decision.
 */
export interface Finding {
  readonly origin: FindingOrigin;
  /** Which check produced this, e.g. `"profile-baseline"`. Never a secret. */
  readonly source: string;
  /** Stable machine-readable code, e.g. `"event-baseline"`. */
  readonly code: string;
  readonly decision: Decision;
  /** Human-readable explanation. Never a secret. */
  readonly message: string;
}

export interface LocalFinding extends Finding {
  readonly origin: "local";
}

export interface ExternalFinding extends Finding {
  readonly origin: "external";
}

export interface HumanFinding extends Finding {
  readonly origin: "human";
}

export function localFinding(
  source: string,
  code: string,
  decision: Decision,
  message: string,
): LocalFinding {
  return { origin: "local", source, code, decision, message };
}

export function externalFinding(
  source: string,
  code: string,
  decision: Decision,
  message: string,
): ExternalFinding {
  return { origin: "external", source, code, decision, message };
}

/** An accumulated decision plus the findings that justify it. */
export interface Evaluation {
  readonly decision: Decision;
  readonly findings: readonly Finding[];
}

export const ALLOW_EVALUATION: Evaluation = Object.freeze({
  decision: "allow",
  findings: Object.freeze([]) as readonly Finding[],
});

function assertMonotone(base: Decision, next: Decision, what: string): void {
  if (decisionRank(next) < decisionRank(base)) {
    // Unreachable unless this module is edited incorrectly. Failing loudly is
    // preferable to silently weakening a security decision.
    throw new Error(
      `supplyguard: ${what} attempted to weaken a decision (${base} -> ${next})`,
    );
  }
}

/** Build an evaluation from local policy findings. */
export function evaluateLocal(findings: readonly LocalFinding[]): Evaluation {
  const decision = mostRestrictive(...findings.map((f) => f.decision));
  return { decision, findings: [...findings] };
}

/** Add further local findings. Monotone: can only tighten. */
export function addLocalFindings(
  base: Evaluation,
  findings: readonly LocalFinding[],
): Evaluation {
  if (findings.length === 0) return base;
  const decision = mostRestrictive(base.decision, ...findings.map((f) => f.decision));
  assertMonotone(base.decision, decision, "addLocalFindings");
  return { decision, findings: [...base.findings, ...findings] };
}

/**
 * Fold external provider evidence into a local evaluation (SPEC 6.1, 13.5).
 *
 * This is the ONLY supported way for provider results to reach a decision, and
 * it is structurally incapable of weakening the local decision: the result is
 * `mostRestrictive(local, ...external)`. A clean external result therefore
 * cannot turn a local `ask`/`deny` into `allow`.
 */
export function withExternalEvidence(
  base: Evaluation,
  external: readonly ExternalFinding[],
): Evaluation {
  if (external.length === 0) return base;
  const decision = mostRestrictive(base.decision, ...external.map((f) => f.decision));
  assertMonotone(base.decision, decision, "withExternalEvidence");
  return { decision, findings: [...base.findings, ...external] };
}

/**
 * Evidence that a human -- not the agent -- answered a gate.
 *
 * Only `src/core/approval.ts` constructs this, and it only does so after an
 * interactive `ctx.ui` prompt returned an explicit answer. Nothing in the
 * engine derives a grant from tool-call input or model output, so the agent
 * has no path to approving its own trust decision (SPEC 17.1, 27.7).
 */
export interface HumanApprovalGrant {
  readonly verifiedBy: "human-ui";
  readonly approved: boolean;
  /** Machine-readable outcome reason, e.g. `"headless-fail-closed"`. */
  readonly reason: string;
  /** ISO-8601 timestamp of the answer. */
  readonly at: string;
}

/**
 * Resolve a pending `ask` using a human grant.
 *
 * - `allow`/`warn` are untouched: there was no gate to answer.
 * - `deny` is untouched: M1 has no override mechanism (scoped overrides are
 *   M4), and an approval prompt is never shown for a denial.
 * - `ask` becomes `allow` on approval and `deny` otherwise.
 */
export function applyHumanApproval(
  base: Evaluation,
  grant: HumanApprovalGrant,
): Evaluation {
  if (base.decision !== "ask") return base;

  const finding: HumanFinding = {
    origin: "human",
    source: "human-approval",
    code: grant.approved ? "approved-once" : "not-approved",
    decision: grant.approved ? "allow" : "deny",
    message: grant.approved
      ? `Approved once by a human at ${grant.at}.`
      : `Not approved by a human (${grant.reason}).`,
  };

  return {
    decision: grant.approved ? "allow" : "deny",
    findings: [...base.findings, finding],
  };
}

/** Findings that justify the decision, most restrictive first. */
export function decisiveFindings(evaluation: Evaluation): readonly Finding[] {
  return evaluation.findings.filter((f) => f.decision === evaluation.decision);
}

/** Short single-line explanation suitable for a block reason or notification. */
export function explain(evaluation: Evaluation): string {
  const decisive = decisiveFindings(evaluation);
  if (decisive.length === 0) return `SupplyGuard: ${evaluation.decision}`;
  return decisive.map((f) => f.message).join(" ");
}
