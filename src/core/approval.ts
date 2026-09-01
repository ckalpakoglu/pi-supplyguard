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

import type { HumanApprovalGrant } from "./decisions.ts";
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
  notify?(message: string, level?: "info" | "warning" | "error"): void | Promise<void>;
}

export const APPROVE_ONCE = "Approve once";
export const DENY = "Deny";

export const APPROVAL_REASONS = [
  "approved-once",
  "denied-by-human",
  "no-response",
  "headless-fail-closed",
  "ui-error",
] as const;

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
