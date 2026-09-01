/**
 * pi-supplyguard — Pi extension entrypoint (SPEC 19).
 *
 * Wiring only: this file connects the Pi host to the ecosystem-agnostic core.
 * Policy lives in `src/core`, ecosystem knowledge lives in `src/adapters`.
 *
 * M1 scope: `tool_call` interception, configuration, profiles, decisions,
 * audit and UI. NO ecosystem adapters are registered yet, so no supply-chain
 * events are produced and ordinary development is unaffected — while the full
 * pipeline is genuinely wired and exercised end to end.
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
  CommandDefinition,
  ExtensionAPI,
  ExtensionContext,
  ToolCallEvent,
  ToolCallEventResult,
} from "@earendil-works/pi-coding-agent";

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
import { evaluateToolCall, type EngineContext } from "./core/engine.ts";
import type { NormalizedToolCall } from "./core/events.ts";
import {
  maxProfile,
  parseProfile,
  profileRank,
  PROFILES,
  type Profile,
} from "./core/profiles.ts";
import { loadState, saveState, setProjectState } from "./core/state.ts";

export interface RuntimeOptions {
  /** M1 default: an empty registry. Tests and later milestones inject one. */
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
  /** Session-scoped tightening floor; never persisted, never lowered. */
  sessionProfileFloor(): Profile | undefined;
  registry(): AdapterRegistry;
}

interface ProjectContext {
  readonly repoRoot: string;
  readonly paths: SupplyGuardPaths;
  readonly loaded: LoadedConfig;
  readonly branch?: string;
}

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
  const registry = options.registry ?? createAdapterRegistry();
  const now = options.now ?? (() => new Date());
  const projects = new Map<string, ProjectContext>();
  const configWarningsAnnounced = new Set<string>();

  /** Session-scoped tightening (SPEC 8.2 "scoped runtime decision"). */
  let sessionFloor: Profile | undefined;

  async function projectContext(cwd: string): Promise<ProjectContext> {
    const cached = projects.get(cwd);
    if (cached !== undefined) return cached;

    const repoRoot = await resolveRepoRoot(cwd);
    const paths = resolvePaths(repoRoot, options.env ?? process.env, options.home);
    const loaded = await loadConfig({ repoRoot, paths });
    const branch = await detectGitBranch(repoRoot);

    const context: ProjectContext = {
      repoRoot,
      paths,
      loaded,
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

  return {
    registry: () => registry,
    sessionProfileFloor: () => sessionFloor,

    async onToolCall(event, ctx) {
      const project = await projectContext(ctx.cwd);
      await announceConfigWarnings(project, ctx);

      const profile = effective(project);
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
        ...(project.branch === undefined ? {} : { branch: project.branch }),
      };

      const outcome = await evaluateToolCall(normalizeToolCall(event), engineCtx);

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
    },

    async statusCommand(_args, ctx) {
      const project = await projectContext(ctx.cwd);
      const config = project.loaded.config;
      const profile = effective(project);

      const sources = project.loaded.sources
        .map((source) =>
          source.path === undefined
            ? `    compiled safe minimums   applied`
            : `    ${source.kind.padEnd(24)} ${source.status}  ${source.path}`,
        )
        .join("\n");

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
          registry.size() === 0 ? " (M1 skeleton: no adapters yet)" : ""
        }`,
        `  Release cooldown     ${config.releaseAgeMinimumDays} days (enforced from M4)`,
        `  Audit                ${config.auditEnabled ? "enabled" : "disabled"}  ${project.paths.audit}`,
        `  Local state          ${project.paths.state}`,
        `  Session              ${ctx.hasUI ? "interactive" : "headless"} (${ctx.mode})`,
        `  Enforcement          M1 skeleton — tool calls are classified and gated;`,
        `                       ecosystem detection arrives with the Go adapter (M2).`,
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
}
