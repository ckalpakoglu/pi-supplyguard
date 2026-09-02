/**
 * Release cooldown (SPEC 11.1).
 *
 * A package version that was published an hour ago has been seen by nobody. A
 * compromised release is at its most dangerous before anyone has looked at it,
 * so SupplyGuard treats "very new" as a risk signal in its own right, separate
 * from any vulnerability database.
 *
 * ECOSYSTEM-AGNOSTIC: this module turns a publication date into a decision.
 * Finding the date is an adapter's job -- for Go that means the module proxy,
 * for npm it would be the registry.
 */

import type { Decision } from "./decisions.ts";
import type { Profile } from "./profiles.ts";

/**
 * What an adapter could learn about when an artifact was published.
 *
 * `not-applicable` is a distinct outcome from `unavailable`, and the difference
 * is load-bearing: a private module is deliberately never looked up, and
 * treating that silence as a provider failure would make Paranoid unable to
 * take an internal dependency at all.
 */
export type ReleaseLookup =
  | { readonly kind: "known"; readonly publishedAt: Date }
  | { readonly kind: "not-applicable"; readonly reason: string }
  | { readonly kind: "unavailable"; readonly reason: string };

export interface ReleaseAgeAssessment {
  readonly decision: Decision;
  /** Non-secret explanation, shown to the human and written to the audit log. */
  readonly message: string;
  /**
   * True when a human may lift this specific denial once (SPEC 17.2).
   *
   * A young artifact is a judgement call, so Hardened and Paranoid allow a
   * scoped override. A provider that could not answer at all is NOT
   * overridable in Paranoid: SPEC 17.3 is explicit that an outage must not
   * become a recurring bypass.
   */
  readonly overridable: boolean;
  /** Paranoid exceptional overrides require a human-entered reason. */
  readonly reasonRequired: boolean;
  readonly ageDays?: number;
}

const MS_PER_DAY = 24 * 60 * 60 * 1000;

export function ageInDays(publishedAt: Date, now: Date): number {
  return (now.getTime() - publishedAt.getTime()) / MS_PER_DAY;
}

/**
 * Apply SPEC 11.1 to one artifact.
 *
 *     standard   WARN + ASK
 *     hardened   DENY with an explicit one-shot override
 *     paranoid   DENY with a reason-required exceptional override
 */
export function assessReleaseAge(
  lookup: ReleaseLookup,
  options: {
    readonly profile: Profile;
    readonly minimumDays: number;
    readonly now: Date;
    readonly artifact: string;
    readonly version: string;
  },
): ReleaseAgeAssessment | undefined {
  const { profile, minimumDays, now, artifact, version } = options;
  const subject = `${artifact}@${version}`;

  if (lookup.kind === "not-applicable") {
    // Nothing was queried and nothing is claimed. The cooldown guards against
    // freshly published PUBLIC artifacts; it has no opinion here.
    return undefined;
  }

  if (lookup.kind === "unavailable") {
    if (profile === "paranoid") {
      return {
        decision: "deny",
        message:
          `The release date of ${subject} could not be determined (${lookup.reason}), and ` +
          `paranoid does not admit an artifact it cannot age-check. Restore access or ` +
          `change the profile deliberately; this is not a one-shot exception.`,
        overridable: false,
        reasonRequired: false,
      };
    }
    return {
      decision: "warn",
      message:
        `The release date of ${subject} could not be determined (${lookup.reason}); ` +
        `the ${minimumDays}-day cooldown could not be checked.`,
      overridable: false,
      reasonRequired: false,
    };
  }

  const days = ageInDays(lookup.publishedAt, now);
  if (days >= minimumDays) {
    return {
      decision: "allow",
      message: `${subject} was published ${Math.floor(days)} days ago (cooldown ${minimumDays}).`,
      overridable: false,
      reasonRequired: false,
      ageDays: Math.floor(days),
    };
  }

  const rounded = Math.max(0, Math.floor(days));
  const tooNew =
    `${subject} was published ${rounded} day(s) ago, inside the ${minimumDays}-day ` +
    `release cooldown.`;

  if (profile === "standard") {
    return {
      decision: "warn",
      message: `${tooNew} Standard warns and still asks a human.`,
      overridable: false,
      reasonRequired: false,
      ageDays: rounded,
    };
  }

  return {
    decision: "deny",
    message: `${tooNew} ${profile === "paranoid" ? "Paranoid" : "Hardened"} denies it.`,
    overridable: true,
    reasonRequired: profile === "paranoid",
    ageDays: rounded,
  };
}
