/**
 * Human approval gate (SPEC 17).
 *
 * Approval is a security primitive: the agent cannot approve its own trust
 * decision. Two properties make that structural rather than aspirational.
 *
 * 1. The only producer of a `HumanApprovalGrant` is this module, and the only
 *    way it produces an approving grant is an explicit answer from a real
 *    interactive prompt. No grant is ever derived from tool input, model
 *    output or configuration.
 * 2. Without an interactive UI there is no human, so there is no approval:
 *    headless sessions FAIL CLOSED (`approved: false`). A missing UI must never
 *    be read as consent.
 */

import type { HumanApprovalGrant, HumanOverrideGrant } from "./decisions.ts";
import type { Profile } from "./profiles.ts";

/**
 * The narrow slice of `ctx.ui` the gate needs.
 *
 * Depending on a port rather than the Pi host object keeps the security-critical
 * path testable without the host, and keeps the rest of `ctx` out of reach.
 */
export interface ApprovalUi {
  readonly hasUI: boolean;
  select(
    title: string,
    options: readonly string[],
    opts?: { readonly timeout?: number },
  ): Promise<string | undefined>;
  /** Free text from the human. Required for a Paranoid exceptional override. */
  input?(
    title: string,
    placeholder?: string,
    opts?: { readonly timeout?: number },
  ): Promise<string | undefined>;
  notify?(message: string, level?: "info" | "warning" | "error"): void | Promise<void>;
}

export const APPROVE_ONCE = "Approve once";
export const DENY = "Deny";
export const OVERRIDE_ONCE = "Override once";
export const KEEP_DENIAL = "Keep the denial";

export const APPROVAL_REASONS = [
  "approved-once",
  "denied-by-human",
  "no-response",
  "headless-fail-closed",
  "ui-error",
] as const;

export const OVERRIDE_REASONS = [
  "overridden-once",
  "declined-by-human",
  "no-response",
  "headless-fail-closed",
  "ui-error",
  "reason-required",
] as const;

export type OverrideReason = (typeof OVERRIDE_REASONS)[number];

export type ApprovalReason = (typeof APPROVAL_REASONS)[number];

export interface ApprovalRequest {
  readonly title: string;
  /** Non-secret detail lines shown to the human, in display order. */
  readonly lines: readonly string[];
  readonly profile: Profile;
}

export interface ApprovalResult {
  readonly grant: HumanApprovalGrant;
  readonly reason: ApprovalReason;
  /** True when no prompt could be shown because the session is headless. */
  readonly headless: boolean;
}

export interface ApprovalOptions {
  /** Optional prompt timeout in ms. A timeout is NOT approval. */
  readonly timeout?: number;
  readonly now?: () => Date;
}

function grant(approved: boolean, reason: ApprovalReason, at: string): HumanApprovalGrant {
  return { verifiedBy: "human-ui", approved, reason, at };
}

/**
 * Ask a human to approve one operation, once.
 *
 * Every non-affirmative outcome -- headless session, dismissed prompt, timeout,
 * UI failure -- results in `approved: false`.
 */
export async function requestHumanApproval(
  request: ApprovalRequest,
  ui: ApprovalUi,
  options: ApprovalOptions = {},
): Promise<ApprovalResult> {
  const at = (options.now ?? (() => new Date()))().toISOString();

  if (!ui.hasUI) {
    // SECURITY: headless fail-closed. No human is reachable, so the gate
    // cannot be satisfied. The caller audits this with the reason below.
    return { grant: grant(false, "headless-fail-closed", at), reason: "headless-fail-closed", headless: true };
  }

  const title = request.title;
  const body = [...request.lines, `Profile: ${request.profile}`].join("\n");

  let answer: string | undefined;
  try {
    answer = await ui.select(
      `${title}\n\n${body}`,
      [APPROVE_ONCE, DENY],
      options.timeout === undefined ? undefined : { timeout: options.timeout },
    );
  } catch {
    return { grant: grant(false, "ui-error", at), reason: "ui-error", headless: false };
  }

  if (answer === APPROVE_ONCE) {
    return { grant: grant(true, "approved-once", at), reason: "approved-once", headless: false };
  }
  if (answer === DENY) {
    return { grant: grant(false, "denied-by-human", at), reason: "denied-by-human", headless: false };
  }

  // `undefined` covers dismissal and timeout. Neither is consent.
  return { grant: grant(false, "no-response", at), reason: "no-response", headless: false };
}

export interface OverrideRequest {
  readonly title: string;
  /** Non-secret detail lines shown to the human, in display order. */
  readonly lines: readonly string[];
  readonly profile: Profile;
  /** SPEC 11.1 -- Paranoid exceptional overrides require a written reason. */
  readonly reasonRequired: boolean;
}

export interface OverrideResult {
  readonly grant: HumanOverrideGrant;
  readonly reason: OverrideReason;
  readonly headless: boolean;
}

function overrideGrant(
  granted: boolean,
  at: string,
  reason?: string,
): HumanOverrideGrant {
  return {
    verifiedBy: "human-ui",
    granted,
    at,
    ...(reason === undefined ? {} : { reason }),
  };
}

/**
 * Offer a human the chance to waive one denial, once (SPEC 17.2).
 *
 * Scoped by the caller to one policy, one artifact, one version and one
 * execution; nothing here is remembered. Every non-affirmative outcome leaves
 * the denial standing, and a Paranoid override without a typed reason is one of
 * them: an exceptional override with no stated reason is not an exception, it
 * is a habit.
 */
export async function requestHumanOverride(
  request: OverrideRequest,
  ui: ApprovalUi,
  options: ApprovalOptions = {},
): Promise<OverrideResult> {
  const at = (options.now ?? (() => new Date()))().toISOString();

  if (!ui.hasUI) {
    return {
      grant: overrideGrant(false, at),
      reason: "headless-fail-closed",
      headless: true,
    };
  }

  const body = [...request.lines, `Profile: ${request.profile}`].join("\n");

  let answer: string | undefined;
  try {
    answer = await ui.select(
      `${request.title}\n\n${body}`,
      [KEEP_DENIAL, OVERRIDE_ONCE],
      options.timeout === undefined ? undefined : { timeout: options.timeout },
    );
  } catch {
    return { grant: overrideGrant(false, at), reason: "ui-error", headless: false };
  }

  if (answer !== OVERRIDE_ONCE) {
    return {
      grant: overrideGrant(false, at),
      reason: answer === KEEP_DENIAL ? "declined-by-human" : "no-response",
      headless: false,
    };
  }

  if (!request.reasonRequired) {
    return { grant: overrideGrant(true, at), reason: "overridden-once", headless: false };
  }

  if (ui.input === undefined) {
    // The profile demands a written reason and this UI cannot take one. The
    // denial stands rather than being waived without the required evidence.
    return { grant: overrideGrant(false, at), reason: "reason-required", headless: false };
  }

  let typed: string | undefined;
  try {
    typed = await ui.input(
      "SupplyGuard — reason for this exceptional override",
      "Why is this artifact being admitted despite the policy?",
      options.timeout === undefined ? undefined : { timeout: options.timeout },
    );
  } catch {
    return { grant: overrideGrant(false, at), reason: "ui-error", headless: false };
  }

  const reason = typed?.trim() ?? "";
  if (reason === "") {
    return { grant: overrideGrant(false, at), reason: "reason-required", headless: false };
  }

  return {
    grant: overrideGrant(true, at, reason.slice(0, 500)),
    reason: "overridden-once",
    headless: false,
  };
}
