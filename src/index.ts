/**
 * pi-supplyguard — Pi extension entrypoint (SPEC 19).
 *
 * Wiring only: this file connects the Pi host to the ecosystem-agnostic core.
 * Policy lives in `src/core`, ecosystem knowledge lives in `src/adapters`.
 *
 * M1 established `tool_call` interception, configuration, profiles, decisions,
 * audit and UI. M2 registered the first ecosystem adapter (Go), so Go command
 * operations produce real supply-chain events and are gated. M3 adds the state
 * this layer has to own for manifest reconciliation (SPEC 14): the
 * sensitive-file baseline each repository was last seen in, whether the
 * previous call was allowed to change it, and the persisted answers to
 * ask-once project questions (SPEC 9.2). Everything else still resolves to
 * ALLOW: ordinary development is unaffected.
 *
 * KNOWN BYPASS VECTOR (documented, not fixed in M1)
 * -------------------------------------------------
 * The Pi host lets a `tool_call` handler mutate `event.input`, and mutations
 * are NOT re-validated. A handler registered after SupplyGuard could therefore
 * rewrite a command that SupplyGuard already approved. SupplyGuard itself never
 * rewrites tool input; it only allows or blocks. Defending against a hostile
 * co-installed extension is out of scope for M1 and is tracked for M9.
 */

import { access } from "node:fs/promises";
import { dirname, join } from "node:path";

import type {
  AgentToolResult,
  CommandDefinition,
  ExtensionAPI,
  ExtensionContext,
  ToolCallEvent,
  ToolCallEventResult,
  ToolDefinition,
} from "@earendil-works/pi-coding-agent";

import { createGoAdapter } from "./adapters/go/index.ts";
import { createAdapterRegistry, type AdapterRegistry } from "./adapters/registry.ts";
import type { ApprovalUi } from "./core/approval.ts";
import {
  createAuditSink,
  detectGitBranch,
  NULL_AUDIT_SINK,
  type AuditRecord,
  type AuditSink,
} from "./core/audit.ts";
import {
  loadConfig,
  resolvePaths,
  type LoadedConfig,
  type PathEnvironment,
  type SupplyGuardPaths,
} from "./core/config.ts";
import {
  evaluateToolCall,
  type EngineContext,
  type ProjectDecisionResolver,
  type ResolvedProjectDecision,
} from "./core/engine.ts";
import type { NormalizedToolCall } from "./core/events.ts";
import {
  createJustificationStore,
  JUSTIFY_TOOL,
  JUSTIFY_TOOL_PARAMETERS,
  parseJustification,
  type JustificationStore,
} from "./core/justification.ts";
import type { ManifestSnapshot } from "./core/manifest.ts";
import {
  maxProfile,
  parseProfile,
  profileRank,
  PROFILES,
  type Profile,
} from "./core/profiles.ts";
import {
  getProjectDecisions,
  loadState,
  saveState,
  setProjectDecision,
  setProjectState,
} from "./core/state.ts";

export interface RuntimeOptions {
  /** Defaults to the production registry. Tests inject their own. */
  readonly registry?: AdapterRegistry;
  readonly env?: PathEnvironment;
  readonly home?: string;
  readonly now?: () => Date;
}

export interface SupplyGuardRuntime {
  onToolCall(
    event: ToolCallEvent,
    ctx: ExtensionContext,
  ): Promise<ToolCallEventResult | undefined>;
  statusCommand(args: string, ctx: ExtensionContext): Promise<void>;
  profileCommand(args: string, ctx: ExtensionContext): Promise<void>;
  /** The `supplyguard_justify_dependency` tool body (SPEC 11.2). */
  justifyTool(params: unknown, ctx: ExtensionContext): Promise<AgentToolResult>;
  /** Session-scoped tightening floor; never persisted, never lowered. */
  sessionProfileFloor(): Profile | undefined;
  registry(): AdapterRegistry;
}

interface ProjectContext {
  readonly repoRoot: string;
  readonly paths: SupplyGuardPaths;
  readonly loaded: LoadedConfig;
  readonly loadedAt: number;
  readonly branch?: string;
}

/**
 * What SupplyGuard remembers about a repository for the length of a session.
 *
 * The manifest baseline is deliberately NOT persisted across sessions. A
 * snapshot from a previous session would turn every commit, branch switch and
 * editor save made while Pi was not running into an "unapproved mutation" on
 * the next start. SupplyGuard reports what it observed while it was watching
 * (see `docs/KNOWN-GAPS.md`).
 */
interface RepoSession {
  baseline?: ManifestSnapshot;
  /** The previous call was allowed and legitimately rewrites tracked files. */
  expectManifestChange: boolean;
  /** Project questions already put to this human in this session. */
  readonly asked: Set<string>;
  /** Answers read from durable state, cached so every call does not re-read it. */
  stored?: Readonly<Record<string, string>>;
  /** Pending dependency justifications (SPEC 11.2); in-memory, one-shot. */
  readonly justifications: JustificationStore;
}

/**
 * How long a loaded configuration is reused before it is re-read.
 *
 * Without this, adding or tightening `.supplyguard.yaml` mid-session would
 * have no effect until Pi restarted. Staleness is bounded and can only ever
 * withhold a TIGHTENING for a few seconds: configuration layers may never
 * weaken (see `tightenConfig`), so a stale copy is never more permissive than
 * the file on disk.
 *
 * ponytail: time-based invalidation. Switch to stat/mtime comparison only if
 * the reload ever shows up in a profile.
 */
const CONFIG_TTL_MS = 5_000;

/** Walk up from `cwd` to the nearest directory containing `.git`. */
async function resolveRepoRoot(cwd: string): Promise<string> {
  let current = cwd;
  for (let i = 0; i < 64; i += 1) {
    try {
      await access(join(current, ".git"));
      return current;
    } catch {
      const parent = dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  return cwd;
}

function normalizeToolCall(event: ToolCallEvent): NormalizedToolCall {
  const raw: unknown = event.input;
  const input =
    typeof raw === "object" && raw !== null && !Array.isArray(raw)
      ? (raw as Record<string, unknown>)
      : {};
  return {
    toolName: event.toolName,
    input,
    ...(event.toolCallId === undefined ? {} : { toolCallId: event.toolCallId }),
  };
}

function uiPort(ctx: ExtensionContext): ApprovalUi {
  return {
    hasUI: ctx.hasUI,
    select: (title, options, opts) => ctx.ui.select(title, options, opts),
    notify: (message, level) => ctx.ui.notify(message, level),
  };
}

function notify(
  ctx: ExtensionContext,
  message: string,
  level: "info" | "warning" | "error",
): void {
  try {
    void ctx.ui.notify(message, level);
  } catch {
    // A UI failure must never break a tool call or a decision.
  }
}

export function createRuntime(options: RuntimeOptions = {}): SupplyGuardRuntime {
  const registry = options.registry ?? createAdapterRegistry([createGoAdapter()]);
  const now = options.now ?? (() => new Date());
  const projects = new Map<string, ProjectContext>();
  const sessions = new Map<string, RepoSession>();
  const configWarningsAnnounced = new Set<string>();

  function repoSession(repoRoot: string): RepoSession {
    const existing = sessions.get(repoRoot);
    if (existing !== undefined) return existing;
    const created: RepoSession = {
      expectManifestChange: false,
      asked: new Set(),
      justifications: createJustificationStore(),
    };
    sessions.set(repoRoot, created);
    return created;
  }

  /** Session-scoped tightening (SPEC 8.2 "scoped runtime decision"). */
  let sessionFloor: Profile | undefined;

  async function projectContext(cwd: string): Promise<ProjectContext> {
    const at = now().getTime();
    const cached = projects.get(cwd);
    if (cached !== undefined && at - cached.loadedAt < CONFIG_TTL_MS) return cached;

    const repoRoot = await resolveRepoRoot(cwd);
    const paths = resolvePaths(repoRoot, options.env ?? process.env, options.home);
    const loaded = await loadConfig({ repoRoot, paths });
    const branch = await detectGitBranch(repoRoot);

    const context: ProjectContext = {
      repoRoot,
      paths,
      loaded,
      loadedAt: at,
      ...(branch === undefined ? {} : { branch }),
    };
    projects.set(cwd, context);
    return context;
  }

  function auditSink(project: ProjectContext): AuditSink {
    return project.loaded.config.auditEnabled
      ? createAuditSink(project.paths.audit)
      : NULL_AUDIT_SINK;
  }

  function effective(project: ProjectContext): Profile {
    return sessionFloor === undefined
      ? project.loaded.config.profile
      : maxProfile(project.loaded.config.profile, sessionFloor);
  }

  async function writeAudit(
    project: ProjectContext,
    record: AuditRecord,
  ): Promise<void> {
    try {
      await auditSink(project)(record);
    } catch {
      // Reported through the caller's UI path; never fatal.
    }
  }

  async function announceConfigWarnings(
    project: ProjectContext,
    ctx: ExtensionContext,
  ): Promise<void> {
    if (project.loaded.warnings.length === 0) return;
    if (configWarningsAnnounced.has(project.repoRoot)) return;
    configWarningsAnnounced.add(project.repoRoot);

    notify(
      ctx,
      `SupplyGuard configuration notices:\n${project.loaded.warnings
        .map((w) => `- ${w}`)
        .join("\n")}`,
      "warning",
    );

    await writeAudit(project, {
      timestamp: now().toISOString(),
      kind: "config",
      profile: effective(project),
      session: ctx.sessionManager.getSessionId(),
      cwd: project.repoRoot,
      headless: !ctx.hasUI,
      message: "configuration layer notices",
      notes: project.loaded.warnings,
      ...(project.branch === undefined ? {} : { branch: project.branch }),
    });
  }

  async function rememberProfile(project: ProjectContext, profile: Profile): Promise<void> {
    try {
      const state = await loadState(project.paths.state);
      await saveState(
        project.paths.state,
        setProjectState(state, project.repoRoot, {
          lastEffectiveProfile: profile,
          lastSeenAt: now().toISOString(),
        }),
      );
    } catch {
      // Remembered state is advisory; failing to write it never changes a
      // decision and never grants trust.
    }
  }

  /**
   * Resolve one ask-once project question (SPEC 9.2, 13.3).
   *
   * Order: a stored human answer wins; otherwise a headless session takes the
   * request's conservative value WITHOUT persisting it; otherwise the human is
   * asked once per session and an explicit answer is persisted and audited.
   *
   * SECURITY: a dismissed or timed-out prompt is `unanswered`, never a value.
   * The adapter then falls back to its own conservative default, exactly as it
   * would before anyone was asked.
   */
  function projectDecisionResolver(
    project: ProjectContext,
    ctx: ExtensionContext,
  ): ProjectDecisionResolver {
    return async (request) => {
      const session = repoSession(project.repoRoot);
      if (session.stored === undefined) {
        session.stored = Object.fromEntries(
          Object.entries(
            getProjectDecisions(await loadState(project.paths.state), project.repoRoot),
          ).map(([id, decision]) => [id, decision.value]),
        );
      }
      const stored = session.stored[request.id];
      // A remembered answer is not news: it is recorded in the audit log of the
      // call where the human gave it, and repeating it on every later call
      // would bury the records that matter.
      if (stored !== undefined) return { value: stored, source: "stored" };

      if (!ctx.hasUI) {
        // SPEC 13.3 / 9.3: headless sessions are not asked and are not
        // silently answered on a human's behalf; the choice is audited.
        return {
          value: request.headlessValue,
          source: "headless-default",
          note: request.headlessNote,
        };
      }

      if (session.asked.has(request.id)) {
        return { source: "unanswered", note: `${request.id}: already asked this session` };
      }
      session.asked.add(request.id);

      let answer: string | undefined;
      try {
        answer = await ctx.ui.select(
          request.question,
          request.options.map((option) => option.label),
        );
      } catch {
        answer = undefined;
      }

      const chosen = request.options.find((option) => option.label === answer);
      if (chosen === undefined) {
        return {
          source: "unanswered",
          note: `${request.id}: not answered; the conservative default applies`,
        };
      }

      const decidedAt = now().toISOString();
      session.stored = { ...session.stored, [request.id]: chosen.value };
      try {
        // Re-read immediately before writing: another repository's answer may
        // have landed in the same file since this session cached its view.
        await saveState(
          project.paths.state,
          setProjectDecision(await loadState(project.paths.state), project.repoRoot, request.id, {
            value: chosen.value,
            decidedAt,
          }),
        );
      } catch {
        // Failing to remember an answer means asking again next session. It
        // never grants trust, so it must not break the call.
      }

      await writeAudit(project, {
        timestamp: decidedAt,
        kind: "project-decision",
        profile: effective(project),
        session: ctx.sessionManager.getSessionId(),
        cwd: project.repoRoot,
        headless: false,
        message: `project decision ${request.id} = ${chosen.value}`,
        ...(project.branch === undefined ? {} : { branch: project.branch }),
      });

      const resolved: ResolvedProjectDecision = { value: chosen.value, source: "human" };
      return resolved;
    };
  }

  /** The real tool-call path. Wrapped by `onToolCall`, which fails closed. */
  async function handleToolCall(
    event: ToolCallEvent,
    ctx: ExtensionContext,
  ): Promise<ToolCallEventResult | undefined> {
    const project = await projectContext(ctx.cwd);
    await announceConfigWarnings(project, ctx);

    const profile = effective(project);
    const session = repoSession(project.repoRoot);
    const engineCtx: EngineContext = {
      repoRoot: project.repoRoot,
      sessionId: ctx.sessionManager.getSessionId(),
      profile,
      hasUI: ctx.hasUI,
      registry,
      ui: uiPort(ctx),
      audit: auditSink(project),
      auditEnabled: project.loaded.config.auditEnabled,
      now,
      resolveProjectDecision: projectDecisionResolver(project, ctx),
      justifications: session.justifications,
      manifestChangeExpected: session.expectManifestChange,
      ...(session.baseline === undefined ? {} : { manifestBaseline: session.baseline }),
      ...(project.branch === undefined ? {} : { branch: project.branch }),
    };

    const outcome = await evaluateToolCall(normalizeToolCall(event), engineCtx);

    // SPEC 14.2: the baseline advances only when the observed state was
    // accepted. After a DENY it stays put, so the rejected mutation is
    // reconciled again on the next call instead of being inherited as clean.
    if (!outcome.blocked) session.baseline = outcome.manifestSnapshot;
    // SECURITY: only an operation a human APPROVED may vouch for the file
    // changes that follow it. "Not blocked" is far too weak a test -- it is
    // also true of every allowed call, so any command that merely looked like a
    // manifest writer would launder the next call's mutations. Every Go
    // operation that writes a manifest is a THIRD_PARTY_MUTATION and therefore
    // passes a human gate, so nothing legitimate is lost.
    session.expectManifestChange =
      outcome.expectsManifestChange && outcome.approval?.granted === true;

    for (const warning of outcome.warnings) {
      notify(ctx, `SupplyGuard: ${warning}`, "warning");
    }

    if (outcome.decision !== "allow") {
      await rememberProfile(project, profile);
    }

    if (outcome.blocked) {
      return { block: true, reason: `SupplyGuard (${profile}): ${outcome.reason}` };
    }

    if (outcome.decision === "warn") {
      notify(ctx, `SupplyGuard (${profile}): ${outcome.reason}`, "warning");
    }

    // ALLOW: no opinion, proceed with normal Pi behavior.
    return undefined;
  }

  return {
    registry: () => registry,
    sessionProfileFloor: () => sessionFloor,

    /**
     * SECURITY: this whole body is guarded.
     *
     * `evaluateToolCall` already converts its own internal failures into a
     * DENY, but the wiring above it -- resolving the repository, loading
     * configuration, reading the session id -- used to be unguarded. A
     * rejected `tool_call` handler is very likely treated by the host as "no
     * opinion", which would turn a SupplyGuard crash into a silent policy
     * bypass. Failing closed is loud and recoverable; failing open is neither.
     */
    async onToolCall(event, ctx) {
      try {
        return await handleToolCall(event, ctx);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        notify(
          ctx,
          `SupplyGuard could not evaluate this tool call (${message}); failing closed. ` +
            `Fix the underlying problem or disable the extension deliberately.`,
          "error",
        );
        return {
          block: true,
          reason: `SupplyGuard: internal error (${message}); failing closed.`,
        };
      }
    },

    /**
     * Record the agent's rationale for a dependency it is about to take on.
     *
     * SECURITY: recording a justification grants nothing. It is evidence the
     * human reads at the gate, and its absence is what turns a dependency
     * operation into a DENY (SPEC 11.2). The agent still cannot approve its own
     * trust decision (SPEC 17.1).
     */
    async justifyTool(params, ctx) {
      const project = await projectContext(ctx.cwd);
      const at = now().toISOString();
      const parsed = parseJustification(params, at);

      if (!parsed.ok) {
        return {
          content: [{ type: "text", text: parsed.message }],
          isError: true,
        };
      }

      const justification = parsed.justification;
      repoSession(project.repoRoot).justifications.record(justification);

      await writeAudit(project, {
        timestamp: at,
        kind: "justification",
        profile: effective(project),
        session: ctx.sessionManager.getSessionId(),
        cwd: project.repoRoot,
        headless: !ctx.hasUI,
        artifact: justification.artifact,
        version: justification.version,
        message: `dependency justification recorded: ${justification.purpose}`,
        notes: [
          `stdlibConsidered=${justification.stdlibConsidered}`,
          `stdlibInsufficientReason=${justification.stdlibInsufficientReason}`,
        ],
        ...(project.branch === undefined ? {} : { branch: project.branch }),
      });

      return {
        content: [
          {
            type: "text",
            text:
              `Recorded a justification for ${justification.artifact}@${justification.version}. ` +
              `Run the dependency operation now: it will be put to a human for approval, ` +
              `and the justification is consumed by that one operation. A different ` +
              `version needs its own justification.`,
          },
        ],
      };
    },

    async statusCommand(_args, ctx) {
      const project = await projectContext(ctx.cwd);
      const config = project.loaded.config;
      const profile = effective(project);
      const session = repoSession(project.repoRoot);
      const state = await loadState(project.paths.state);
      const decisions = Object.fromEntries(
        Object.entries(getProjectDecisions(state, project.repoRoot)).map(
          ([id, decision]) => [id, decision.value],
        ),
      );
      const ecosystemState = await registry.describe({
        repoRoot: project.repoRoot,
        profile,
        decisions,
      });

      const sources = project.loaded.sources
        .map((source) =>
          source.path === undefined
            ? `    compiled safe minimums   applied`
            : `    ${source.kind.padEnd(24)} ${source.status}  ${source.path}`,
        )
        .join("\n");

      const adapters = registry
        .list()
        .map((a) => a.id)
        .join(", ");

      const lines = [
        "SupplyGuard",
        `  Effective profile    ${profile}`,
        `  Configured profile   ${config.profile}`,
        `  Session tightening   ${sessionFloor ?? "none"}`,
        `  Repository           ${project.repoRoot}${
          project.branch === undefined ? "" : ` (${project.branch})`
        }`,
        `  Config sources`,
        sources,
        `  Ecosystem adapters   ${registry.size()} registered${
          registry.size() === 0 ? " (none)" : ` (${adapters})`
        }`,
        `  Release cooldown     ${config.releaseAgeMinimumDays} days (enforced from M4)`,
        `  Watched files        ${registry.sensitivePaths().join(", ") || "none"}`,
        `  Manifest baseline    ${
          session.baseline === undefined
            ? "not established yet (set on the first tool call)"
            : "established for this session"
        }`,
        `  Ecosystem state`,
        ...(ecosystemState.length === 0
          ? ["    none reported"]
          : ecosystemState.map((line) => `    ${line}`)),
        `  Project decisions    ${
          Object.entries(decisions)
            .map(([id, value]) => `${id}=${value}`)
            .join(", ") || "none recorded"
        }`,
        `  Audit                ${config.auditEnabled ? "enabled" : "disabled"}  ${project.paths.audit}`,
        `  Local state          ${project.paths.state}`,
        `  Session              ${ctx.hasUI ? "interactive" : "headless"} (${ctx.mode})`,
        `  Enforcement          Go command gate (M2) and manifest reconciliation`,
        `                       plus vendor state (M3) active. Release cooldown,`,
        `                       identity, vulnerability and Socket checks arrive`,
        `                       in M4-M7.`,
      ];

      if (project.loaded.warnings.length > 0) {
        lines.push("  Warnings");
        for (const warning of project.loaded.warnings) lines.push(`    - ${warning}`);
      }

      notify(ctx, lines.join("\n"), "info");
    },

    /**
     * Display the effective profile, or tighten it for THIS SESSION ONLY.
     *
     * SECURITY: this command can never lower the effective profile and never
     * writes to global or project configuration (SPEC 8.2). Loosening is a
     * deliberate, reviewable edit of a configuration file, not a chat command.
     */
    async profileCommand(args, ctx) {
      const project = await projectContext(ctx.cwd);
      const current = effective(project);
      const requested = args.trim();

      if (requested === "") {
        notify(
          ctx,
          [
            `SupplyGuard profile: ${current}`,
            `  configured: ${project.loaded.config.profile}`,
            `  session tightening: ${sessionFloor ?? "none"}`,
            `  usage: /supplyguard-profile <${PROFILES.join("|")}>  (tightens this session only)`,
          ].join("\n"),
          "info",
        );
        return;
      }

      const target = parseProfile(requested);
      if (target === undefined) {
        notify(
          ctx,
          `SupplyGuard: unknown profile "${requested}". Valid profiles: ${PROFILES.join(", ")}.`,
          "error",
        );
        return;
      }

      if (profileRank(target) <= profileRank(current)) {
        notify(
          ctx,
          `SupplyGuard: profile stays ${current}. This command can only tighten the ` +
            `effective profile for the current session; lowering it requires editing ` +
            `configuration.`,
          "warning",
        );
        return;
      }

      sessionFloor = maxProfile(sessionFloor ?? target, target);
      const updated = effective(project);
      notify(ctx, `SupplyGuard: profile tightened to ${updated} for this session.`, "info");

      await writeAudit(project, {
        timestamp: now().toISOString(),
        kind: "command",
        profile: updated,
        session: ctx.sessionManager.getSessionId(),
        cwd: project.repoRoot,
        headless: !ctx.hasUI,
        message: `session profile tightened from ${current} to ${updated}`,
        ...(project.branch === undefined ? {} : { branch: project.branch }),
      });
    },
  };
}

const STATUS_COMMAND: string = "supplyguard-status";
const PROFILE_COMMAND: string = "supplyguard-profile";

export default function supplyguard(pi: ExtensionAPI): void {
  const runtime = createRuntime();

  pi.on("tool_call", (event, ctx) => runtime.onToolCall(event, ctx));

  const status: CommandDefinition = {
    description: "Show the effective SupplyGuard profile, configuration sources and state",
    handler: (args, ctx) => runtime.statusCommand(args, ctx),
  };
  const profile: CommandDefinition = {
    description: "Show the effective profile, or tighten it for this session only",
    handler: (args, ctx) => runtime.profileCommand(args, ctx),
  };

  pi.registerCommand(STATUS_COMMAND, status);
  pi.registerCommand(PROFILE_COMMAND, profile);

  const justify: ToolDefinition = {
    name: JUSTIFY_TOOL,
    label: "SupplyGuard justify dependency",
    description:
      "Record why a third-party dependency is needed, before adding, upgrading or " +
      "executing it. SupplyGuard denies dependency operations that have no recorded " +
      "justification for the exact module and version. Recording a justification is " +
      "not approval: a human still decides.",
    promptSnippet:
      `${JUSTIFY_TOOL} — state why a dependency is needed before adding or upgrading it`,
    promptGuidelines: [
      `Before any command that adds, upgrades or executes a third-party dependency, call ` +
        `${JUSTIFY_TOOL} with the exact module and version, what it is for, and why the ` +
        `standard library is insufficient. SupplyGuard denies unjustified dependency ` +
        `operations, and each justification covers one module at one version for one run.`,
    ],
    parameters: JUSTIFY_TOOL_PARAMETERS,
    execute: (_toolCallId, params, _signal, _onUpdate, ctx) => runtime.justifyTool(params, ctx),
  };

  pi.registerTool(justify);
}
