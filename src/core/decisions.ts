/**
 * Decision model (SPEC 6.1).
 *
 *     ALLOW < WARN < ASK < DENY
 *
 * The most restrictive decision always wins. This module is the ONLY place
 * where decisions are combined, and every combinator here is monotone: the
 * result can never be less restrictive than the base it was derived from.
 *
 * There are exactly two deliberate exceptions, both requiring evidence that a
 * real human answered a real prompt (`src/core/approval.ts`):
 *
 * - `applyHumanApproval` lowers a pending `ask` to `allow`. It can never touch
 *   a `deny`.
 * - `applyHumanOverride` lowers a `deny` to `allow`, and ONLY when every
 *   finding that produced the denial is marked `overridable` (SPEC 17.2). An
 *   invariant violation -- a floating version, a checksum bypass, a missing
 *   justification -- is not overridable, so no prompt can lift it.
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
  /**
   * True when a human may lift THIS finding once, for one artifact at one
   * version, for one execution (SPEC 17.2).
   *
   * Defaults to absent, i.e. not overridable: a check has to opt in to being
   * waivable, and the ones that do are judgement calls (release cooldown),
   * never invariants.
   */
  readonly overridable?: boolean;
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
  options: { readonly overridable?: boolean } = {},
): LocalFinding {
  return {
    origin: "local",
    source,
    code,
    decision,
    message,
    ...(options.overridable === true ? { overridable: true } : {}),
  };
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

/**
 * Evidence that a human waived a specific denial (SPEC 17.2).
 *
 * Constructed only by `src/core/approval.ts`, and only after an interactive
 * prompt returned an explicit choice. `reason` is present when the profile
 * demanded one; nothing else can supply it.
 */
export interface HumanOverrideGrant {
  readonly verifiedBy: "human-ui";
  readonly granted: boolean;
  readonly at: string;
  readonly reason?: string;
}

/**
 * Can this denial be waived at all?
 *
 * Every finding that produced the denial must opt in. One non-overridable
 * decisive finding -- a floating version, a checksum bypass -- makes the whole
 * denial final, however many waivable ones sit beside it.
 */
export function isOverridable(evaluation: Evaluation): boolean {
  if (evaluation.decision !== "deny") return false;
  const decisive = decisiveFindings(evaluation);
  return decisive.length > 0 && decisive.every((finding) => finding.overridable === true);
}

/** True when any decisive finding demands a written reason (SPEC 11.1). */
export function overrideNeedsReason(
  evaluation: Evaluation,
  reasonRequiredCodes: ReadonlySet<string>,
): boolean {
  return decisiveFindings(evaluation).some((finding) => reasonRequiredCodes.has(finding.code));
}

/**
 * Lower a denial a human explicitly waived.
 *
 * SECURITY: this is the only function in the codebase that can weaken a `deny`,
 * so it refuses unless `isOverridable` holds -- the guard is here, not at the
 * call site, because a call site can be edited by someone who has not read
 * SPEC 17.2. A refused or ungranted override leaves the denial exactly as it
 * was, with the attempt recorded.
 */
export function applyHumanOverride(
  base: Evaluation,
  grant: HumanOverrideGrant,
): Evaluation {
  if (!isOverridable(base)) {
    return grant.granted
      ? {
          decision: base.decision,
          findings: [
            ...base.findings,
            {
              origin: "human",
              source: "human-override",
              code: "override-refused",
              decision: base.decision,
              message:
                `An override was offered for a denial that is not waivable; the denial ` +
                `stands.`,
            },
          ],
        }
      : base;
  }

  if (!grant.granted) {
    return {
      decision: "deny",
      findings: [
        ...base.findings,
        {
          origin: "human",
          source: "human-override",
          code: "override-declined",
          decision: "deny",
          message: `No override was granted at ${grant.at}.`,
        },
      ],
    };
  }

  return {
    decision: "allow",
    findings: [
      ...base.findings,
      {
        origin: "human",
        source: "human-override",
        code: "override-granted",
        decision: "allow",
        message:
          `Overridden once by a human at ${grant.at}` +
          `${grant.reason === undefined ? "" : `: ${grant.reason}`}.`,
      },
    ],
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
