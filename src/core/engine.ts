/**
 * Policy engine (SPEC 5, 6.1).
 *
 * Pipeline for every tool call:
 *
 *     snapshot sensitive files      (SPEC 14 -- reconcile the PREVIOUS call)
 *       -> classify (adapters)
 *       -> normalized events, from the call AND from observed file mutations
 *       -> project state (vendor model), once its questions are answered
 *       -> local baseline policy
 *       -> external evidence (additive, tightening only)
 *       -> human gate when the result is ASK
 *       -> audit
 *
 * RECONCILIATION IS RETROSPECTIVE BY CONSTRUCTION. The host fires this handler
 * BEFORE a tool runs, so a file mutation can only be observed on the next call.
 * That is still an enforcement boundary: the agent cannot keep working after
 * editing `go.mod` behind the gate's back, because the next tool call carries
 * the unapproved change with it.
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
  mostRestrictive,
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
import { mostSevereClassification } from "./events.ts";
import {
  describeMutation,
  diffManifestSnapshot,
  EMPTY_SNAPSHOT,
  readManifestSnapshot,
  type ManifestSnapshot,
} from "./manifest.ts";
import {
  describeJustification,
  JUSTIFY_TOOL,
  needsJustification,
  type Justification,
  type JustificationStore,
} from "./justification.ts";
import { baselineForClassification, baselineForEvent, type Profile } from "./profiles.ts";
import type { AdapterRegistry, ProjectDecisionRequest } from "../adapters/registry.ts";

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

/**
 * How a project-level question was answered (SPEC 9.2, 13.3).
 *
 * `unanswered` is a real outcome: a dismissed prompt is not consent, and the
 * adapter must then fall back to its own conservative default.
 */
export interface ResolvedProjectDecision {
  readonly value?: string;
  readonly source: "stored" | "human" | "headless-default" | "unanswered";
  /** Non-secret note for the audit record. */
  readonly note?: string;
}

/**
 * Resolve one ask-once project question: stored answer, human prompt, or the
 * request's conservative headless value. Supplied by the Pi wiring layer,
 * which owns persistence.
 */
export type ProjectDecisionResolver = (
  request: ProjectDecisionRequest,
) => Promise<ResolvedProjectDecision>;

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
  /**
   * Sensitive-file state as of the previous tool call, or `undefined` for the
   * first call in a repository. SupplyGuard reports what it observed while it
   * was watching; it never invents a history from before it was loaded.
   */
  readonly manifestBaseline?: ManifestSnapshot;
  /**
   * True when the PREVIOUS call was an approved operation that legitimately
   * rewrites tracked files. Its manifest changes are then reconciled and
   * audited rather than re-gated.
   */
  readonly manifestChangeExpected?: boolean;
  readonly resolveProjectDecision?: ProjectDecisionResolver;
  /**
   * Pending dependency justifications (SPEC 11.2), recorded by the agent
   * through the `supplyguard_justify_dependency` tool.
   *
   * Absent means the requirement is not enforced -- which is only ever the case
   * in tests of the pre-M4 pipeline. The Pi wiring layer always supplies one.
   */
  readonly justifications?: JustificationStore;
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
  /**
   * Sensitive-file state as read at the start of this evaluation.
   *
   * The caller stores it as the next baseline ONLY when the call was not
   * denied: forgetting a rejected mutation would let a second tool call
   * inherit it as the accepted state.
   */
  readonly manifestSnapshot: ManifestSnapshot;
  /** True when this call is expected to rewrite tracked files (SPEC 14.2). */
  readonly expectsManifestChange: boolean;
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
    const baseline = baselineForEvent(event.eventClass, profile);
    // An adapter may assert a floor for an invariant that does not vary by
    // profile. mostRestrictive keeps this monotone: it can only tighten.
    const decision = mostRestrictive(baseline, event.minimumDecision ?? "allow");
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
  justifications: ReadonlyMap<string, Justification>,
): string[] {
  const lines = [`Tool: ${call.toolName}`];
  for (const event of events) {
    lines.push(describeEvent(event));
    // SPEC 11.3: the human reads the agent's own rationale next to the change
    // it is asking for, not just the module name.
    const justification = justifications.get(describeEvent(event));
    if (justification !== undefined) lines.push(...describeJustification(justification));
  }
  for (const finding of evaluation.findings) {
    lines.push(`- [${finding.decision}] ${finding.message}`);
  }
  return lines;
}

/**
 * Require a justification for every new trust decision (SPEC 11.2).
 *
 * SECURITY: a missing justification is a DENY, not a silently thinner approval
 * prompt. If an unjustified dependency merely asked, the tool would be
 * decorative -- the agent would never call it, and the human would keep
 * approving decisions with no stated purpose, which is the situation SPEC 11
 * exists to end. The denial names the tool, so the agent can correct itself.
 *
 * The justifications collected here are CONSUMED: one artifact, one version,
 * one execution (SPEC 17.2).
 */
function collectJustifications(
  events: readonly SupplyChainEvent[],
  store: JustificationStore | undefined,
): { readonly findings: LocalFinding[]; readonly used: Map<string, Justification> } {
  const findings: LocalFinding[] = [];
  const used = new Map<string, Justification>();
  if (store === undefined) return { findings, used };

  for (const event of events) {
    if (!needsJustification(event)) continue;
    const artifact = event.artifact ?? "";
    const version = event.version ?? "";

    const justification = store.take(artifact, version);
    if (justification === undefined) {
      findings.push(
        localFinding(
          "justification",
          "missing-justification",
          "deny",
          `${artifact}@${version} has no recorded justification. The agent must call ` +
            `\`${JUSTIFY_TOOL}\` with the exact module and version, what it is for, and ` +
            `why the standard library is insufficient, before this operation can be ` +
            `put to a human.`,
        ),
      );
      continue;
    }

    used.set(describeEvent(event), justification);
    findings.push(
      localFinding(
        "justification",
        "justification-recorded",
        "ask",
        `${artifact}@${version} was justified by the agent: ${justification.purpose}`,
      ),
    );
  }

  return { findings, used };
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
      // An evaluation that failed observed nothing, so it must not advance the
      // baseline: the next call re-reads the repository and reconciles again.
      manifestSnapshot: ctx.manifestBaseline ?? EMPTY_SNAPSHOT,
      expectsManifestChange: false,
    };
    return outcome;
  }
}

async function run(call: NormalizedToolCall, ctx: EngineContext): Promise<EngineOutcome> {
  const warnings: string[] = [];
  const notes: string[] = [];
  const now = ctx.now ?? (() => new Date());
  const adapterCtx = { repoRoot: ctx.repoRoot, profile: ctx.profile };

  // --- SPEC 14: reconcile what happened since the previous tool call --------
  const watched = ctx.registry.sensitivePaths();
  const manifestSnapshot =
    watched.length === 0 ? EMPTY_SNAPSHOT : await readManifestSnapshot(ctx.repoRoot, watched);
  const mutations =
    ctx.manifestBaseline === undefined
      ? []
      : diffManifestSnapshot(ctx.manifestBaseline, manifestSnapshot);

  const inspection = await ctx.registry.inspectToolCall(call, adapterCtx);

  const errors = [...inspection.errors];
  notes.push(...inspection.notes);

  const mutationEvents: SupplyChainEvent[] = [];
  if (mutations.length > 0) {
    for (const mutation of mutations) notes.push(describeMutation(mutation));

    if (ctx.manifestChangeExpected === true) {
      // The previous call was an approved operation that rewrites manifests.
      // Its own trust decision already happened; recording the resulting file
      // changes as evidence is right, re-gating them is not.
      notes.push(
        `reconciled ${mutations.length} tracked file change(s) with the preceding approved operation`,
      );
    } else {
      const reconciled = await ctx.registry.inspectFileMutations(mutations, adapterCtx);
      mutationEvents.push(...reconciled.events);
      errors.push(...reconciled.errors);
      notes.push(...reconciled.notes);
    }
  }

  const classification = mostSevereClassification(
    inspection.classification,
    ...mutationEvents.map((event) => event.classification),
  );

  // Fast path: nothing in this call can touch third-party trust, and nothing
  // changed on disk. Installing SupplyGuard must not tax ordinary development,
  // and harmless calls are not audited or sent anywhere (SPEC 5.1, 2.2).
  if (
    classification === "SUPPLY_CHAIN_IRRELEVANT" &&
    inspection.events.length === 0 &&
    mutations.length === 0 &&
    errors.length === 0
  ) {
    return {
      decision: "allow",
      evaluation: evaluateLocal([]),
      classification,
      events: inspection.events,
      blocked: false,
      reason: "",
      audited: false,
      warnings,
      manifestSnapshot,
      expectsManifestChange: inspection.expectsManifestChange,
    };
  }

  // --- Project-level questions and state (SPEC 9.2, 9.4) -------------------
  const decisions: Record<string, string> = {};
  if (ctx.resolveProjectDecision !== undefined) {
    for (const request of await ctx.registry.projectDecisions({ ...adapterCtx, decisions })) {
      const resolved = await ctx.resolveProjectDecision(request);
      if (resolved.value !== undefined) decisions[request.id] = resolved.value;
      // A stored answer was already audited when the human gave it; repeating
      // it on every later call would bury the records that matter.
      if (resolved.source !== "stored") {
        notes.push(
          resolved.note ??
            `project decision ${request.id}: ${resolved.value ?? "unanswered"} (${resolved.source})`,
        );
      }
    }
  }

  const callEvents: readonly SupplyChainEvent[] = [...inspection.events, ...mutationEvents];
  const projectState = await ctx.registry.inspectProjectState({
    ...adapterCtx,
    decisions,
    classification,
    events: callEvents,
  });
  errors.push(...projectState.errors);
  notes.push(...projectState.notes);

  const events: readonly SupplyChainEvent[] = [...callEvents, ...projectState.events];

  const justified = collectJustifications(events, ctx.justifications);

  let evaluation = evaluateLocal([
    ...baselineFindings(classification, events, ctx.profile),
    ...justified.findings,
  ]);

  if (errors.length > 0) {
    const unknownRiskDecision = baselineForClassification("UNKNOWN_RISK", ctx.profile);
    evaluation = addLocalFindings(
      evaluation,
      errors.map((error) =>
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
        lines: approvalLines(call, events, evaluation, justified.used),
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

  const auditNotes = [...(events.length > 1 ? events.map(describeEvent) : []), ...notes];

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
      ...(auditNotes.length === 0 ? {} : { notes: auditNotes }),
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
    manifestSnapshot,
    expectsManifestChange: inspection.expectsManifestChange,
  };
}
