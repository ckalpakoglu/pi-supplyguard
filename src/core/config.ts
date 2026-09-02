/**
 * Configuration, paths and precedence (SPEC 8).
 *
 *     compiled safe minimums
 *     -> global configuration
 *     -> project configuration
 *     -> scoped runtime decision
 *
 * Each later stage may only TIGHTEN the previous one. A weakening attempt is
 * never silently honoured: it is ignored and reported as a warning so it can
 * be surfaced and audited.
 *
 * Missing configuration files are not an error -- SupplyGuard falls back to the
 * compiled safe minimums.
 */

import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";

import { DEFAULT_PROFILE, maxProfile, parseProfile, type Profile } from "./profiles.ts";
import { isEmptyDocument, parseYaml } from "./yaml.ts";

/** SPEC 8.1 -- canonical configuration and state paths. */
export interface SupplyGuardPaths {
  readonly globalConfig: string;
  readonly globalTrust: string;
  readonly projectConfig: string;
  readonly projectTrust: string;
  readonly state: string;
  readonly audit: string;
}

export interface PathEnvironment {
  readonly XDG_CONFIG_HOME?: string | undefined;
  readonly XDG_STATE_HOME?: string | undefined;
}

/**
 * Resolve all SupplyGuard paths.
 *
 * Per the XDG basedir specification a relative `XDG_*_HOME` value is invalid
 * and must be ignored; honouring one would place security state in an
 * attacker-influenced relative location.
 */
export function resolvePaths(
  repoRoot: string,
  env: PathEnvironment = process.env,
  home: string = homedir(),
): SupplyGuardPaths {
  const configHome = absoluteOr(env.XDG_CONFIG_HOME, join(home, ".config"));
  const stateHome = absoluteOr(env.XDG_STATE_HOME, join(home, ".local", "state"));

  return {
    globalConfig: join(configHome, "pi-supplyguard", "config.yaml"),
    globalTrust: join(configHome, "pi-supplyguard", "trust.yaml"),
    projectConfig: join(repoRoot, ".supplyguard.yaml"),
    projectTrust: join(repoRoot, ".supplyguard-trust.yaml"),
    state: join(stateHome, "pi-supplyguard", "state.json"),
    audit: join(stateHome, "pi-supplyguard", "audit.jsonl"),
  };
}

function absoluteOr(value: string | undefined, fallback: string): string {
  return value !== undefined && value !== "" && isAbsolute(value) ? value : fallback;
}

/**
 * The effective configuration.
 *
 * M1 intentionally models only the knobs the skeleton enforces. Analyzer and
 * provider settings arrive with the milestones that implement them; adding
 * them earlier would mean shipping configuration that silently does nothing.
 */
/**
 * SPEC 8.3 -- how much SupplyGuard leans on Socket.
 *
 *     off       never invoked
 *     auto      used when the CLI is present; its absence is a warning
 *     required  a new dependency needs a Socket verdict; absence is a denial
 *
 * Paranoid raises this to `required` regardless of configuration (SPEC 13.4).
 */
export const SOCKET_MODES = ["off", "auto", "required"] as const;

export type SocketMode = (typeof SOCKET_MODES)[number];

const SOCKET_RANK = { off: 0, auto: 1, required: 2 } as const satisfies Record<SocketMode, number>;

export function socketRank(mode: SocketMode): number {
  return SOCKET_RANK[mode];
}

export function parseSocketMode(value: unknown): SocketMode | undefined {
  if (value === true) return "required";
  if (value === false) return "off";
  return typeof value === "string" && (SOCKET_MODES as readonly string[]).includes(value)
    ? (value as SocketMode)
    : undefined;
}

export interface SupplyGuardConfig {
  readonly version: 1;
  readonly profile: Profile;
  /** SPEC 11.1 -- consumed by M4; carried here so precedence is testable now. */
  readonly releaseAgeMinimumDays: number;
  readonly auditEnabled: boolean;
  readonly socket: SocketMode;
}

/** SPEC 8.2 -- the compiled safe minimums; the floor of every other layer. */
export const COMPILED_SAFE_MINIMUMS: SupplyGuardConfig = Object.freeze({
  version: 1,
  profile: DEFAULT_PROFILE,
  releaseAgeMinimumDays: 10,
  auditEnabled: true,
  // SPEC 4.4: Socket scans are optional and off by default in standard. `auto`
  // means "use it if it is there", which costs an absent operator nothing.
  socket: "auto",
});

/** A partial configuration layer parsed from a file. */
export interface ConfigLayer {
  readonly profile?: Profile;
  readonly releaseAgeMinimumDays?: number;
  readonly auditEnabled?: boolean;
  readonly socket?: SocketMode;
}

export const CONFIG_SOURCE_KINDS = ["compiled", "global", "project"] as const;

export type ConfigSourceKind = (typeof CONFIG_SOURCE_KINDS)[number];

export const CONFIG_SOURCE_STATUSES = [
  "applied",
  "missing",
  "unreadable",
  "invalid",
] as const;

export type ConfigSourceStatus = (typeof CONFIG_SOURCE_STATUSES)[number];

export interface ConfigSource {
  readonly kind: ConfigSourceKind;
  readonly path?: string;
  readonly status: ConfigSourceStatus;
  /** Non-secret notes, e.g. an ignored weakening attempt. */
  readonly notes: readonly string[];
}

export interface LoadedConfig {
  readonly config: SupplyGuardConfig;
  readonly sources: readonly ConfigSource[];
  /** Aggregated non-secret warnings; surfaced in status output and audit. */
  readonly warnings: readonly string[];
}

export interface TightenResult {
  readonly config: SupplyGuardConfig;
  readonly warnings: readonly string[];
}

/**
 * Fold one layer over a base configuration. Tightening only.
 *
 * - `profile`: `max(base, layer)`.
 * - `releaseAgeMinimumDays`: `max(base, layer)` (longer cooldown is stricter).
 * - `auditEnabled`: once enabled it cannot be disabled by a later layer.
 */
export function tightenConfig(
  base: SupplyGuardConfig,
  layer: ConfigLayer,
  layerName: string,
): TightenResult {
  const warnings: string[] = [];

  let profile = base.profile;
  if (layer.profile !== undefined) {
    profile = maxProfile(base.profile, layer.profile);
    if (profile !== layer.profile) {
      warnings.push(
        `${layerName} requested profile "${layer.profile}", which is weaker than the ` +
          `established baseline "${base.profile}"; ignored (a layer may tighten, not weaken).`,
      );
    }
  }

  let releaseAgeMinimumDays = base.releaseAgeMinimumDays;
  if (layer.releaseAgeMinimumDays !== undefined) {
    releaseAgeMinimumDays = Math.max(base.releaseAgeMinimumDays, layer.releaseAgeMinimumDays);
    if (releaseAgeMinimumDays !== layer.releaseAgeMinimumDays) {
      warnings.push(
        `${layerName} requested releaseAge.minimumDays ${layer.releaseAgeMinimumDays}, ` +
          `which is weaker than the established baseline ${base.releaseAgeMinimumDays}; ignored.`,
      );
    }
  }

  let auditEnabled = base.auditEnabled;
  if (layer.auditEnabled !== undefined) {
    auditEnabled = base.auditEnabled || layer.auditEnabled;
    if (auditEnabled !== layer.auditEnabled) {
      warnings.push(
        `${layerName} requested audit.enabled=false, which is weaker than the established ` +
          `baseline audit.enabled=true; ignored.`,
      );
    }
  }

  let socket = base.socket;
  if (layer.socket !== undefined) {
    socket = socketRank(layer.socket) >= socketRank(base.socket) ? layer.socket : base.socket;
    if (socket !== layer.socket) {
      warnings.push(
        `${layerName} requested socket.enabled "${layer.socket}", which is weaker than the ` +
          `established baseline "${base.socket}"; ignored.`,
      );
    }
  }

  return {
    config: { version: 1, profile, releaseAgeMinimumDays, auditEnabled, socket },
    warnings,
  };
}

export interface ParsedLayer {
  readonly layer: ConfigLayer;
  readonly warnings: readonly string[];
}

/**
 * Interpret an untrusted parsed YAML document as a configuration layer.
 *
 * Unknown keys are ignored with a warning rather than accepted: silently
 * swallowing `socket:` today and honouring it after an upgrade would change
 * enforcement without review. Malformed values are ignored, never guessed.
 */
export function parseConfigLayer(raw: unknown): ParsedLayer {
  const warnings: string[] = [];

  if (isEmptyDocument(raw)) return { layer: {}, warnings };

  if (typeof raw !== "object" || Array.isArray(raw)) {
    return { layer: {}, warnings: ["configuration root is not a mapping; ignored."] };
  }

  const doc = raw as Record<string, unknown>;
  const layer: {
    profile?: Profile;
    releaseAgeMinimumDays?: number;
    auditEnabled?: boolean;
    socket?: SocketMode;
  } = {};

  if ("profile" in doc) {
    const profile = parseProfile(doc["profile"]);
    if (profile === undefined) {
      warnings.push(`invalid "profile" value; ignored.`);
    } else {
      layer.profile = profile;
    }
  }

  const releaseAge = doc["releaseAge"];
  if (releaseAge !== undefined) {
    const days = readNumber(releaseAge, "minimumDays");
    if (days === undefined) {
      warnings.push(`invalid "releaseAge.minimumDays" value; ignored.`);
    } else {
      layer.releaseAgeMinimumDays = days;
    }
  }

  const audit = doc["audit"];
  if (audit !== undefined) {
    const enabled = readBoolean(audit, "enabled");
    if (enabled === undefined) {
      warnings.push(`invalid "audit.enabled" value; ignored.`);
    } else {
      layer.auditEnabled = enabled;
    }
  }

  const socket = doc["socket"];
  if (socket !== undefined) {
    const mode = parseSocketMode(
      typeof socket === "object" && socket !== null && !Array.isArray(socket)
        ? (socket as Record<string, unknown>)["enabled"]
        : socket,
    );
    if (mode === undefined) {
      warnings.push(`invalid "socket.enabled" value; ignored.`);
    } else {
      layer.socket = mode;
    }
  }

  const known = new Set(["version", "profile", "releaseAge", "audit", "socket"]);
  for (const key of Object.keys(doc)) {
    if (!known.has(key)) {
      warnings.push(`unsupported configuration key "${key}"; ignored in this version.`);
    }
  }

  return { layer, warnings };
}

function readNumber(container: unknown, key: string): number | undefined {
  if (typeof container !== "object" || container === null) return undefined;
  const value = (container as Record<string, unknown>)[key];
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return undefined;
  return value;
}

function readBoolean(container: unknown, key: string): boolean | undefined {
  if (typeof container !== "object" || container === null) return undefined;
  const value = (container as Record<string, unknown>)[key];
  return typeof value === "boolean" ? value : undefined;
}

interface FileLayer {
  readonly source: ConfigSource;
  readonly layer: ConfigLayer;
}

async function loadLayerFile(kind: ConfigSourceKind, path: string): Promise<FileLayer> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") {
      return { source: { kind, path, status: "missing", notes: [] }, layer: {} };
    }
    return {
      source: {
        kind,
        path,
        status: "unreadable",
        notes: [`could not be read (${code ?? "unknown error"}); falling back to the baseline.`],
      },
      layer: {},
    };
  }

  const parsed = parseYaml(text);
  if (!parsed.ok) {
    return {
      source: {
        kind,
        path,
        status: "invalid",
        notes: [`could not be parsed (${parsed.error}); falling back to the baseline.`],
      },
      layer: {},
    };
  }

  const interpreted = parseConfigLayer(parsed.value);
  return {
    source: { kind, path, status: "applied", notes: interpreted.warnings },
    layer: interpreted.layer,
  };
}

export interface LoadConfigOptions {
  readonly repoRoot: string;
  readonly env?: PathEnvironment;
  readonly home?: string;
  /** Injectable for tests; defaults to `resolvePaths`. */
  readonly paths?: SupplyGuardPaths;
}

/** Load the effective configuration following SPEC 8.2 precedence. */
export async function loadConfig(options: LoadConfigOptions): Promise<LoadedConfig> {
  const paths =
    options.paths ??
    resolvePaths(options.repoRoot, options.env ?? process.env, options.home ?? homedir());

  const sources: ConfigSource[] = [
    { kind: "compiled", status: "applied", notes: [] },
  ];
  const warnings: string[] = [];

  let config = COMPILED_SAFE_MINIMUMS;

  for (const [kind, path, label] of [
    ["global", paths.globalConfig, "global configuration"],
    ["project", paths.projectConfig, "project configuration"],
  ] as const) {
    const loaded = await loadLayerFile(kind, path);
    const tightened = tightenConfig(config, loaded.layer, label);
    config = tightened.config;

    const notes = [...loaded.source.notes, ...tightened.warnings];
    sources.push({ ...loaded.source, notes });
    for (const note of notes) warnings.push(`${label}: ${note}`);
  }

  return { config, sources, warnings };
}
