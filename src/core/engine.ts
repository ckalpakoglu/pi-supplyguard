/**
 * Policy engine (SPEC 5, 6.1).
 *
 * Pipeline for every tool call:
 *
 *     classify (adapters)
 *       -> normalized events
 *       -> local baseline policy
 *       -> external evidence (additive, tightening only)
 *       -> human gate when the result is ASK
 *       -> audit
 *
 * ECOSYSTEM-AGNOSTIC BY CONSTRUCTION: this file contains no package-manager
 * names, command strings, manifest filenames or registry hosts. Everything
 * ecosystem-specific reaches the engine as an opaque adapter id inside a
 * normalized event (SPEC 7, 27.1).
 */

import { requestHumanApproval, type ApprovalReason, type ApprovalUi } from "./approval.ts";
import type { AuditRecord, AuditSink } from "./audit.ts";
import {
  addLocalFindings,
  applyHumanApproval,
  evaluateLocal,
  explain,
  localFinding,
  withExternalEvidence,
  type Decision,
  type Evaluation,
  type ExternalFinding,
  type LocalFinding,
} from "./decisions.ts";
import type {
  NormalizedToolCall,
  SupplyChainEvent,
  ToolCallClassification,
} from "./events.ts";
import { baselineForClassification, baselineForEvent, type Profile } from "./profiles.ts";
import type { AdapterRegistry } from "../adapters/registry.ts";

/**
 * Optional external intelligence hook (SPEC 13, M6/M7).
 *
 * It can only return findings, and findings from providers can only be folded
 * in through `withExternalEvidence`, which cannot weaken a local decision.
 */
export type ExternalEvidenceProvider = (
  events: readonly SupplyChainEvent[],
  ctx: EngineContext,
) => Promise<readonly ExternalFinding[]>;

export interface EngineContext {
  readonly repoRoot: string;
  readonly sessionId: string;
  readonly profile: Profile;
  readonly hasUI: boolean;
  readonly registry: AdapterRegistry;
  readonly ui: ApprovalUi;
  readonly audit: AuditSink;
  readonly auditEnabled: boolean;
  readonly branch?: string;
  readonly now?: () => Date;
  readonly externalEvidence?: ExternalEvidenceProvider;
  /** Optional prompt timeout in ms; a timeout is never treated as approval. */
  readonly approvalTimeout?: number;
}

export interface EngineOutcome {
  readonly decision: Decision;
  readonly evaluation: Evaluation;
  readonly classification: ToolCallClassification;
  readonly events: readonly SupplyChainEvent[];
  /** True when the tool call must not run. */
  readonly blocked: boolean;
  readonly reason: string;
  readonly approval?: { readonly required: true; readonly granted: boolean; readonly reason: ApprovalReason };
  readonly audited: boolean;
  /** Non-fatal problems, e.g. the audit sink failing. Never secrets. */
  readonly warnings: readonly string[];
}

function describeEvent(event: SupplyChainEvent): string {
  const artifact = event.artifact === undefined ? "" : ` ${event.artifact}`;
  const version = event.version === undefined ? "" : `@${event.version}`;
  return `${event.eventClass}${artifact}${version} [${event.ecosystem}]: ${event.summary}`;
}

function baselineFindings(
  classification: ToolCallClassification,
  events: readonly SupplyChainEvent[],
  profile: Profile,
): LocalFinding[] {
  const findings: LocalFinding[] = [];

  const classificationDecision = baselineForClassification(classification, profile);
  if (classificationDecision !== "allow") {
    findings.push(
      localFinding(
        "profile-baseline",
        `classification:${classification}`,
        classificationDecision,
        `Tool call classified ${classification}; ${profile} baseline requires ${classificationDecision}.`,
      ),
    );
  }

  for (const event of events) {
    const decision = baselineForEvent(event.eventClass, profile);
    findings.push(
      localFinding(
        "profile-baseline",
        `event:${event.eventClass}`,
        decision,
        `${describeEvent(event)} -- ${profile} baseline requires ${decision}.`,
      ),
    );
  }

  return findings;
}

function approvalLines(
  call: NormalizedToolCall,
  events: readonly SupplyChainEvent[],
  evaluation: Evaluation,
): string[] {
  const lines = [`Tool: ${call.toolName}`];
  for (const event of events) lines.push(describeEvent(event));
  for (const finding of evaluation.findings) {
    lines.push(`- [${finding.decision}] ${finding.message}`);
  }
  return lines;
}

function primaryEvent(
  events: readonly SupplyChainEvent[],
  decision: Decision,
  profile: Profile,
): SupplyChainEvent | undefined {
  return (
    events.find((event) => baselineForEvent(event.eventClass, profile) === decision) ??
    events[0]
  );
}

/**
 * Evaluate one tool call.
 *
 * Never throws: an internal failure is converted into a DENY with an explicit
 * finding. Failing open would make a SupplyGuard bug a silent policy bypass.
 */
export async function evaluateToolCall(
  call: NormalizedToolCall,
  ctx: EngineContext,
): Promise<EngineOutcome> {
  try {
    return await run(call, ctx);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const evaluation = evaluateLocal([
      localFinding(
        "engine",
        "internal-error",
        "deny",
        `SupplyGuard could not complete its evaluation (${message}); failing closed.`,
      ),
    ]);
    const outcome: EngineOutcome = {
      decision: "deny",
      evaluation,
      classification: "UNKNOWN_RISK",
      events: [],
      blocked: true,
      reason: explain(evaluation),
      audited: false,
      warnings: [`engine error: ${message}`],
    };
    return outcome;
  }
}

async function run(call: NormalizedToolCall, ctx: EngineContext): Promise<EngineOutcome> {
  const warnings: string[] = [];
  const now = ctx.now ?? (() => new Date());

  const inspection = await ctx.registry.inspectToolCall(call, {
    repoRoot: ctx.repoRoot,
    profile: ctx.profile,
  });

  const { classification, events } = inspection;

  // Fast path: nothing in this call can touch third-party trust. Installing
  // SupplyGuard must not tax ordinary development, and harmless calls are not
  // audited or sent anywhere (SPEC 5.1, 2.2).
  if (
    classification === "SUPPLY_CHAIN_IRRELEVANT" &&
    events.length === 0 &&
    inspection.errors.length === 0
  ) {
    return {
      decision: "allow",
      evaluation: evaluateLocal([]),
      classification,
      events,
      blocked: false,
      reason: "",
      audited: false,
      warnings,
    };
  }

  let evaluation = evaluateLocal(baselineFindings(classification, events, ctx.profile));

  if (inspection.errors.length > 0) {
    const unknownRiskDecision = baselineForClassification("UNKNOWN_RISK", ctx.profile);
    evaluation = addLocalFindings(
      evaluation,
      inspection.errors.map((error) =>
        localFinding(
          "adapter-registry",
          "adapter-error",
          unknownRiskDecision,
          `Ecosystem adapter "${error.adapterId}" failed to inspect this call (${error.message}); treated as unknown risk.`,
        ),
      ),
    );
  }

  // External intelligence is additive and can only tighten (SPEC 13.5).
  if (ctx.externalEvidence !== undefined && events.length > 0) {
    try {
      const external = await ctx.externalEvidence(events, ctx);
      evaluation = withExternalEvidence(evaluation, external);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      warnings.push(`external evidence provider failed: ${message}`);
      evaluation = addLocalFindings(evaluation, [
        localFinding(
          "external-provider",
          "provider-error",
          "warn",
          `An external security provider failed (${message}); local policy remains authoritative.`,
        ),
      ]);
    }
  }

  const localDecision = evaluation.decision;
  let approval: EngineOutcome["approval"];

  if (localDecision === "ask") {
    const result = await requestHumanApproval(
      {
        title: "SupplyGuard — approval required",
        lines: approvalLines(call, events, evaluation),
        profile: ctx.profile,
      },
      ctx.ui,
      ctx.approvalTimeout === undefined
        ? { now }
        : { now, timeout: ctx.approvalTimeout },
    );

    evaluation = applyHumanApproval(evaluation, result.grant);
    approval = { required: true, granted: result.grant.approved, reason: result.reason };
  }

  // Defensive: nothing may leave the engine still pending. An unresolved ASK
  // would be ambiguous at the enforcement boundary, so it fails closed.
  if (evaluation.decision === "ask") {
    evaluation = addLocalFindings(evaluation, [
      localFinding(
        "engine",
        "unresolved-ask",
        "deny",
        "An approval gate was not resolved; failing closed.",
      ),
    ]);
  }

  const decision = evaluation.decision;
  const blocked = decision === "deny";
  const reason = decision === "allow" ? "" : explain(evaluation);

  let audited = false;
  if (ctx.auditEnabled) {
    const event = primaryEvent(events, localDecision, ctx.profile);
    const record: AuditRecord = {
      timestamp: now().toISOString(),
      kind: "tool-call",
      profile: ctx.profile,
      session: ctx.sessionId,
      cwd: ctx.repoRoot,
      headless: !ctx.hasUI,
      tool: call.toolName,
      classification,
      decision,
      findings: evaluation.findings,
      ...(ctx.branch === undefined ? {} : { branch: ctx.branch }),
      ...(event === undefined
        ? {}
        : {
            event: event.eventClass,
            ecosystem: event.ecosystem,
            ...(event.artifact === undefined ? {} : { artifact: event.artifact }),
            ...(event.version === undefined ? {} : { version: event.version }),
          }),
      ...(approval === undefined ? {} : { approval }),
      ...(events.length > 1 ? { notes: events.map(describeEvent) } : {}),
    };

    try {
      await ctx.audit(record);
      audited = true;
    } catch (error) {
      // An audit failure must never weaken a decision, and must be visible.
      const message = error instanceof Error ? error.message : String(error);
      warnings.push(`audit write failed: ${message}`);
    }
  }

  return {
    decision,
    evaluation,
    classification,
    events,
    blocked,
    reason,
    ...(approval === undefined ? {} : { approval }),
    audited,
    warnings,
  };
}
