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
 * The Pi host lets a `tool_call` handler mutate `event.input`, and omp lets a
 * handler replace it by returning `input` (last wins). Neither host re-runs
 * extension hooks on the revised input. A handler registered after SupplyGuard
 * could therefore rewrite a command that SupplyGuard already approved.
 * SupplyGuard itself never rewrites tool input; it only allows or blocks.
 * Defending against a hostile co-installed extension is out of scope; see
 * `docs/KNOWN-GAPS.md` §1.10.
 */

import { createHash } from "node:crypto";
import { watch } from "node:fs";
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
  ToolResultEvent,
} from "@earendil-works/pi-coding-agent";

import { createGoAdapter } from "./adapters/go/index.ts";
import type { OsvOptions } from "./adapters/go/osv.ts";
import type { ProxyOptions } from "./adapters/go/proxy.ts";
import { createAdapterRegistry, type AdapterRegistry } from "./adapters/registry.ts";
import { createGenericAdapter } from "./generic/index.ts";
import type { ApprovalUi } from "./core/approval.ts";
import {
  createAuditSink,
  detectGitBranch,
  NULL_AUDIT_SINK,
  type AuditRecord,
  type AuditSink,
} from "./core/audit.ts";
import { readFile, writeFile } from "node:fs/promises";
import { parseGoMod } from "./adapters/go/modfile.ts";
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
import { normalizeToolCall } from "./host/tool-input.ts";
import {
  createJustificationStore,
  JUSTIFY_TOOL,
  JUSTIFY_TOOL_PARAMETERS,
  parseJustification,
  needsJustification,
  type JustificationStore,
} from "./core/justification.ts";
import { isPrivateModule, locateModuleSource } from "./analyzers/content.ts";
import { createNpmAdapter } from "./adapters/npm/index.ts";
import type { ManifestSnapshot } from "./core/manifest.ts";
import {
  maxProfile,
  parseProfile,
  profileRank,
  PROFILES,
  type Profile,
} from "./core/profiles.ts";
import { countIdentities, loadTrustCorpus, type TrustCorpus } from "./core/trust.ts";
import {
  createSocketEvidence,
  createSocketProvider,
  type SocketProviderOptions,
} from "./providers/socket/index.ts";
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
  /**
   * Module-proxy access for release-age lookups (SPEC 11.1).
   *
   * Tests MUST set `env: { GOPROXY: "off" }` or inject `fetch`: a suite that
   * silently reaches proxy.golang.org is slow, flaky, and tells a public
   * service which module names appear in this repository's fixtures.
   */
  readonly proxy?: ProxyOptions;
  /**
   * OSV access for vulnerability lookups (SPEC 16).
   *
   * Defaults to the proxy's environment, so `GOPROXY=off` disables both. Tests
   * MUST disable it or inject `fetch`: the suite reaches no network.
   */
  readonly osv?: OsvOptions;
  /**
   * Socket CLI access (SPEC 13).
   *
   * Tests MUST inject `run`: nothing in the suite starts a process.
   */
  readonly socket?: SocketProviderOptions;
  /** Optional Jev analyzer overrides; the analyzer itself is default-off. */
  readonly jev?: {
    readonly baseUrl?: string;
    readonly model?: string;
    /** Test seam: an injected transport. Nothing in the suite reaches the network. */
    readonly post?: (url: string, body: unknown, apiKey: string) => Promise<unknown>;
  };
}

export interface SupplyGuardRuntime {
  onToolCall(
    event: ToolCallEvent,
    ctx: ExtensionContext,
  ): Promise<ToolCallEventResult | undefined>;
  /**
   * A tool finished running; arms the expectation of an approved manifest
   * writer, and audits input revised after the gate (KNOWN-GAPS 1.10).
   */
  onToolResult(event: ToolResultEvent, ctx: ExtensionContext): Promise<void>;
  statusCommand(args: string, ctx: ExtensionContext): Promise<void>;
  /** `/supplyguard-trust init`: seed the corpus from go.mod (M14). */
  trustCommand(args: string, ctx: ExtensionContext): Promise<void>;
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
  /** Protected identities, loaded on the same TTL as configuration (SPEC 12). */
  readonly trust: TrustCorpus;
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
  /**
   * An approved manifest writer has finished running and its changes are not
   * yet reconciled.
   */
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

/**
 * Stable JSON form, so the same input hashes the same on both sides of a
 * tool call. Key order is the only thing normalized; contents are never read.
 */
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    const entries = Object.entries(value)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function uiPort(ctx: ExtensionContext): ApprovalUi {
  return {
    hasUI: ctx.hasUI,
    select: (title, options, opts) => ctx.ui.select(title, options, opts),
    // Paranoid exceptional overrides need a typed reason (SPEC 11.1).
    input: (title, placeholder, opts) => ctx.ui.input(title, placeholder, opts),
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
  const registry =
    options.registry ??
    createAdapterRegistry([
      createGenericAdapter(),
      createGoAdapter(
        options.proxy ?? {},
        options.osv ?? { ...(options.proxy?.env === undefined ? {} : { env: options.proxy.env }) },
      ),
      createNpmAdapter(),
    ]);
  const now = options.now ?? (() => new Date());
  const projects = new Map<string, ProjectContext>();
  const sessions = new Map<string, RepoSession>();
  // Approval-fatigue metric (M10): prompts per session, surfaced in status.
  // More prompts mean less looking; the number exists to be watched.
  const asksBySession = new Map<string, number>();
  // M12: tracked files that changed while no tool call was executing. Best
  // effort and detection-only: reconciliation on the next call remains the
  // gate; this makes the WRITE itself visible, with its timing.
  const outOfBandWrites = new Set<string>();
  const repoWatchers = new Map<string, { close(): void }>();
  const executionsInFlight = new Set<string>();

  function globMatch(pattern: string, value: string): boolean {
    const glob = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*");
    return new RegExp(`^${glob}$`).test(value);
  }

  function startWatcher(repoRoot: string): void {
    if (repoWatchers.has(repoRoot)) return;
    try {
      const watcher = watch(repoRoot, { recursive: true }, (_kind, filename) => {
        if (typeof filename !== "string") return;
        if (executionsInFlight.size > 0) return; // attributable to a running call
        const rel = filename.replace(/\\/g, "/");
        const hit = registry.sensitivePaths().some(
          (path) => rel === path || rel.endsWith(`/${path}`) || globMatch(path, rel),
        );
        if (hit) outOfBandWrites.add(rel);
      });
      repoWatchers.set(repoRoot, watcher);
    } catch {
      // No watcher, no attribution: reconciliation still catches the change.
    }
  }
  // One provider per runtime: health and per-artifact results are cached in it,
  // so a session asks the CLI about a given package once.
  const socketProvider = createSocketProvider(options.socket ?? {});
  const configWarningsAnnounced = new Set<string>();
  // Approved manifest writers, by tool call id, that have not yet reported a
  // result. See `handleToolCall` for why arming waits for `tool_result`.
  const pendingManifestWriters = new Map<string, RepoSession>();
  // Hash of the input SupplyGuard evaluated, by tool call id, for calls that
  // were allowed to run. Compared against the input the tool reports at
  // `tool_result` (KNOWN-GAPS 1.10): a later handler that revised the input
  // after the gate becomes visible instead of silent. Bounded, FIFO.
  const rememberedInputs = new Map<string, string>();
  const REMEMBERED_INPUT_LIMIT = 256;

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
    const trust = await loadTrustCorpus([paths.globalTrust, paths.projectTrust]);

    const context: ProjectContext = {
      repoRoot,
      paths,
      loaded,
      trust,
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

  /** SPEC 13.4 -- paranoid raises Socket to `required` regardless of config. */
  function socketMode(project: ProjectContext): "off" | "auto" | "required" {
    const configured = project.loaded.config.socket;
    if (effective(project) === "paranoid") return "required";
    return configured;
  }

  function effective(project: ProjectContext): Profile {
    return sessionFloor === undefined
      ? project.loaded.config.profile
      : maxProfile(project.loaded.config.profile, sessionFloor);
  }

  /**
   * Compose the engine's single external-evidence slot: Socket, plus the
   * optional Jev analyzer when `jev.enabled` is on AND an API key exists in
   * the environment. Jev is loaded dynamically ON PURPOSE: deleting
   * `src/providers/jev/` must leave a fully working product (KNOWN-GAPS
   * §1.15), and a static import would defeat that.
   */
  function externalEvidenceFor(project: ProjectContext, env: Readonly<Record<string, string | undefined>>) {
    const socket =
      socketMode(project) === "off"
        ? undefined
        : createSocketEvidence(socketProvider, {
            requiredFor: (candidate) => candidate === "paranoid" || socketMode(project) === "required",
          });
    const jevConfigured = project.loaded.config.jevEnabled;

    return async (events: Parameters<NonNullable<EngineContext["externalEvidence"]>>[0], ctx: EngineContext) => {
      const findings = [];
      if (socket !== undefined) findings.push(...(await socket(events, ctx)));
      if (!jevConfigured) return findings;
      const apiKey = env.TYPESAFE_API_KEY ?? env.JEV_API_KEY;
      if (apiKey === undefined || apiKey === "") return findings;

      // Dynamic on purpose: deleting src/providers/jev/ must leave a working
      // product (KNOWN-GAPS 1.15); a static import would defeat that.
      const { createJevAnalyzer } = await import("./providers/jev/index.ts");
      const analyzer = createJevAnalyzer({ enabled: true, apiKey, ...(options.jev ?? {}) });
      const targets = new Map<string, { artifact: string; version: string }>();
      for (const event of events) {
        if (!needsJustification(event)) continue;
        if (event.artifact === undefined || event.version === undefined) continue;
        targets.set(`${event.artifact}@${event.version}`, {
          artifact: event.artifact,
          version: event.version,
        });
      }
      for (const { artifact, version } of targets.values()) {
        if (isPrivateModule(artifact, env)) continue; // goes nowhere, ever
        const located = await locateModuleSource(project.repoRoot, artifact, version, env);
        if (located === undefined) continue; // local scanner already said so
        findings.push(...(await analyzer.evidenceFor({ artifact, version, source: located.root })));
      }

      // M14 repository signals: opt-in, advisory, additive-only.
      if (project.loaded.config.signalsEnabled) {
        const { createRepoSignalsProvider } = await import("./providers/signals/index.ts");
        const provider = createRepoSignalsProvider({
          ...(typeof env.GITHUB_TOKEN === "string" ? { token: env.GITHUB_TOKEN } : {}),
        });
        for (const { artifact, version } of targets.values()) {
          findings.push(...(await provider.evidenceFor(artifact, version)));
        }
      }
      return findings;
    };
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
    const warnings = [...project.loaded.warnings, ...project.trust.warnings];
    if (warnings.length === 0) return;
    if (configWarningsAnnounced.has(project.repoRoot)) return;
    configWarningsAnnounced.add(project.repoRoot);

    notify(
      ctx,
      `SupplyGuard configuration notices:\n${warnings.map((w) => `- ${w}`).join("\n")}`,
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
      notes: warnings,
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

    startWatcher(project.repoRoot);
    // Report tracked writes that landed while nothing was executing, then
    // let this call's reconciliation remain the actual gate.
    if (outOfBandWrites.size > 0) {
      const paths = [...outOfBandWrites].sort();
      outOfBandWrites.clear();
      notify(
        ctx,
        `SupplyGuard: tracked file(s) changed while no tool call was running: ` +
          `${paths.join(", ")}. The next evaluation reconciles them.`,
        "warning",
      );
      await writeAudit(project, {
        timestamp: now().toISOString(),
        kind: "out-of-band-write",
        profile: effective(project),
        session: ctx.sessionManager.getSessionId(),
        cwd: project.repoRoot,
        headless: !ctx.hasUI,
        message: `tracked file(s) changed outside any tool call: ${paths.join(", ")}`,
        ...(project.branch === undefined ? {} : { branch: project.branch }),
      });
    }

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
      ...(socketMode(project) === "off" &&
        !project.loaded.config.jevEnabled &&
        !project.loaded.config.signalsEnabled
        ? {}
        : {
            // Socket plus, when `jev.enabled` is on and a key exists, the
            // optional Jev analyzer; and `signals.enabled` for repository
            // signals. All additive-only.
            externalEvidence: externalEvidenceFor(
              project,
              (options.env ?? process.env) as Readonly<Record<string, string | undefined>>,
            ),
          }),
      justifications: session.justifications,
      releaseAgeMinimumDays: project.loaded.config.releaseAgeMinimumDays,
      trust: project.trust,
      manifestChangeExpected: session.expectManifestChange,
      ...(session.baseline === undefined ? {} : { manifestBaseline: session.baseline }),
      ...(project.branch === undefined ? {} : { branch: project.branch }),
    };

    const call = normalizeToolCall(event);
    const outcome = await evaluateToolCall(call, engineCtx);

    if (outcome.approval?.required === true) {
      const sid = ctx.sessionManager.getSessionId();
      asksBySession.set(sid, (asksBySession.get(sid) ?? 0) + 1);
    }

    // The call now executes: writes it makes are attributable to it and are
    // reconciled on the next call. The window closes at its tool_result.
    if (!outcome.blocked && typeof event.toolCallId === "string") {
      executionsInFlight.add(event.toolCallId);
    }

    // SPEC 14.2: the baseline advances only when the observed state was
    // accepted. After a DENY it stays put, so the rejected mutation is
    // reconciled again on the next call instead of being inherited as clean.
    if (!outcome.blocked) session.baseline = outcome.manifestSnapshot;
    // This call's reconciliation consumed any change that had already landed.
    session.expectManifestChange = false;
    // SECURITY: only an operation a human APPROVED may vouch for the file
    // changes that follow it. "Not blocked" is far too weak a test -- it is
    // also true of every allowed call, so any command that merely looked like a
    // manifest writer would launder the next call's mutations. Every Go
    // operation that writes a manifest is a THIRD_PARTY_MUTATION and therefore
    // passes a human gate, so nothing legitimate is lost.
    //
    // The expectation arms only once the approved call has actually run, on its
    // own `tool_result`. omp runs every `tool_call` hook of a batch before
    // executing any of them, and Pi can execute tools in parallel, so arming
    // here would let a later hook in the same batch clear the flag before the
    // writer ran. A call that never ran -- blocked by another extension,
    // denied by the host, aborted -- vouches for nothing.
    if (outcome.expectsManifestChange && outcome.approval?.granted === true) {
      if (call.toolCallId === undefined) {
        // A host without call ids cannot report which call finished: keep the
        // one-following-call semantics.
        session.expectManifestChange = true;
      } else {
        pendingManifestWriters.set(call.toolCallId, session);
      }
    }

    // The input this gate actually evaluated -- not the normalized copy, and
    // never the contents: only a hash is kept, and only until the call's result.
    if (!outcome.blocked && typeof event.toolCallId === "string") {
      const hash = createHash("sha256")
        .update(canonicalJson(event.input ?? {}))
        .digest("hex");
      if (rememberedInputs.size >= REMEMBERED_INPUT_LIMIT) {
        const oldest = rememberedInputs.keys().next().value;
        if (oldest !== undefined) rememberedInputs.delete(oldest);
      }
      rememberedInputs.set(event.toolCallId, hash);
    }

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

    async onToolResult(event, ctx) {
      // Never throws and never alters the host's result: bookkeeping only.
      try {
        const id: unknown = event?.toolCallId;
        if (typeof id !== "string") return;
        executionsInFlight.delete(id);
        const session = pendingManifestWriters.get(id);
        if (session !== undefined) {
          pendingManifestWriters.delete(id);
          session.expectManifestChange = true;
        }

        // KNOWN-GAPS 1.10: a `tool_call` handler registered after SupplyGuard
        // can rewrite input the gate already judged, and neither host re-runs
        // hooks on the revision. The result carries what actually ran, so a
        // mismatch can at least be made loud. A hash says nothing about the
        // contents; a benign formatter extension can trip this, which is why
        // the answer is a warning, not a block.
        const expected = rememberedInputs.get(id);
        const actual = event?.input;
        if (expected === undefined || typeof actual !== "object" || actual === null) return;
        rememberedInputs.delete(id);
        const hash = createHash("sha256").update(canonicalJson(actual)).digest("hex");
        if (hash === expected) return;

        notify(
          ctx,
          `SupplyGuard: tool "${event.toolName}" ran with input that differs from what ` +
            `SupplyGuard evaluated. A later handler may have revised it after the ` +
            `gate; the revision was not re-checked.`,
          "warning",
        );
        const project = await projectContext(ctx.cwd);
        await writeAudit(project, {
          timestamp: now().toISOString(),
          kind: "input-revision",
          profile: effective(project),
          session: ctx.sessionManager.getSessionId(),
          cwd: project.repoRoot,
          headless: !ctx.hasUI,
          tool: event.toolName,
          message:
            "tool ran with input differing from what SupplyGuard evaluated " +
            "(expected sha256 " + expected.slice(0, 12) + ", got " + hash.slice(0, 12) + ")",
          ...(project.branch === undefined ? {} : { branch: project.branch }),
        });
      } catch {
        // An audit-of-last-resort must never break the host's result handling.
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
        watchedPaths: registry.sensitivePaths(),
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
        `  Jev analyzer         ${
          config.jevEnabled ? "enabled (experimental; ASK-capped)" : "off"
        }`,
        `  Approvals asked      ${
          asksBySession.get(ctx.sessionManager.getSessionId()) ?? 0
        } this session (fatigue metric)`,
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
        `  Release cooldown     ${config.releaseAgeMinimumDays} days`,
        `  Socket               ${socketMode(project)}${
          socketMode(project) === "off" ? "" : ` (CLI: ${(await socketProvider.health()).version ?? "not available"})`
        }`,
        `  Trust corpus         ${
          project.trust.empty
            ? "none — typo/repository-squatting analysis is DISABLED"
            : `${countIdentities(project.trust)} identities (${project.trust.sources.join(", ")})`
        }`,
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
        `  Enforcement          Go command gate (M2), manifest reconciliation and`,
        `                       vendor state (M3), dependency justification and`,
        `                       release cooldown (M4), identity protection (M5)`,
        `                       generic policies (M8), OSV vulnerability data (M6)`,
        `                       and Socket artifact scans (M7) active. Socket`,
        `                       Firewall is deliberately not implemented.`,
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

    async trustCommand(args, ctx) {
      if (args.trim() !== "init") {
        notify(
          ctx,
          "SupplyGuard: usage /supplyguard-trust init — generates .supplyguard-trust.yaml " +
            "from the repository's go.mod",
          "info",
        );
        return;
      }

      const project = await projectContext(ctx.cwd);
      const target = join(project.repoRoot, ".supplyguard-trust.yaml");
      try {
        await access(target);
        notify(
          ctx,
          "SupplyGuard: .supplyguard-trust.yaml already exists; not overwriting it.",
          "warning",
        );
        return;
      } catch {
        // Absent: generate it.
      }

      let goMod: string | undefined;
      try {
        goMod = await readFile(join(project.repoRoot, "go.mod"), "utf8");
      } catch {
        goMod = undefined;
      }
      if (goMod === undefined) {
        notify(ctx, "SupplyGuard: no go.mod found; nothing to seed a corpus from.", "warning");
        return;
      }

      const modules = parseGoMod(goMod).requires.map((r) => r.path);
      const body = [
        "version: 1",
        "protected:",
        "  go:",
        "    modules:",
        ...modules.map((m) => `      - ${m}`),
        "",
      ].join("\n");
      await writeFile(target, body, "utf8");
      await writeAudit(project, {
        timestamp: now().toISOString(),
        kind: "command",
        profile: effective(project),
        session: ctx.sessionManager.getSessionId(),
        cwd: project.repoRoot,
        headless: !ctx.hasUI,
        message: `seeded .supplyguard-trust.yaml from go.mod (${modules.length} modules)`,
        ...(project.branch === undefined ? {} : { branch: project.branch }),
      });
      notify(
        ctx,
        `SupplyGuard: seeded .supplyguard-trust.yaml with ${modules.length} module(s) from ` +
          `go.mod. Review it: the corpus is what typo and squatting analysis protects.`,
        "info",
      );
    },
  };
}

const STATUS_COMMAND: string = "supplyguard-status";
const PROFILE_COMMAND: string = "supplyguard-profile";

export default function supplyguard(pi: ExtensionAPI): void {
  const runtime = createRuntime();

  pi.on("tool_call", (event, ctx) => runtime.onToolCall(event, ctx));
  pi.on("tool_result", (event, ctx) => runtime.onToolResult(event, ctx));

  const status: CommandDefinition = {
    description: "Show the effective SupplyGuard profile, configuration sources and state",
    handler: (args, ctx) => runtime.statusCommand(args, ctx),
  };
  const profile: CommandDefinition = {
    description: "Show the effective profile, or tighten it for this session only",
    handler: (args, ctx) => runtime.profileCommand(args, ctx),
  };
  const trust: CommandDefinition = {
    description: "`init` seeds .supplyguard-trust.yaml from go.mod",
    handler: (args, ctx) => runtime.trustCommand(args, ctx),
  };

  pi.registerCommand(STATUS_COMMAND, status);
  pi.registerCommand(PROFILE_COMMAND, profile);
  pi.registerCommand("supplyguard-trust", trust);

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
    // omp: keep it a top-level tool rather than an `xd://` device, and do not
    // put it behind the exec-tier approval prompt -- it records rationale only
    // and grants nothing.
    loadMode: "essential",
    approval: "read",
    execute: (_toolCallId, params, _signal, _onUpdate, ctx) => runtime.justifyTool(params, ctx),
  };

  pi.registerTool(justify);
}
