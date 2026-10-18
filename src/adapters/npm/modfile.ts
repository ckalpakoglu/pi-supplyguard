/**
 * npm manifest semantics (M13): pure functions, no filesystem.
 *
 * `package.json` carries the intent (dependencies, scripts); the lockfile
 * carries what actually landed. The threat model that matters on npm is the
 * lifecycle script: `postinstall`/`preinstall`/`prepare` in a dependency runs
 * arbitrary code at install time, which is where the real npm incidents
 * (event-stream, ua-parser-js, node-ipc) lived. The lockfile records
 * `hasInstallScript` per package, so the signal is available without touching
 * `node_modules`.
 */

export interface PackageJson {
  readonly name?: string;
  readonly dependencies: Readonly<Record<string, string>>;
  readonly devDependencies: Readonly<Record<string, string>>;
  /** Repo-defined scripts; `prepare` and friends run on install of THIS package. */
  readonly scripts: Readonly<Record<string, string>>;
}

export function parsePackageJson(text: string): PackageJson {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return { dependencies: {}, devDependencies: {}, scripts: {} };
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    return { dependencies: {}, devDependencies: {}, scripts: {} };
  }
  const record = doc as Record<string, unknown>;
  const readMap = (key: string): Record<string, string> => {
    const value = record[key];
    if (typeof value !== "object" || value === null || Array.isArray(value)) return {};
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (typeof v === "string") out[k] = v;
    }
    return out;
  };
  const name = record["name"];
  return {
    ...(typeof name === "string" ? { name } : {}),
    dependencies: readMap("dependencies"),
    devDependencies: readMap("devDependencies"),
    scripts: readMap("scripts"),
  };
}

export interface DependencyChange {
  readonly kind: "add" | "upgrade" | "downgrade" | "remove";
  readonly name: string;
  readonly from?: string;
  readonly to?: string;
}

/** Which lifecycle scripts does a dependency declare? */
const LIFECYCLE = new Set(["preinstall", "install", "postinstall", "prepublish", "prepare"]);

export function lifecycleScripts(pkg: PackageJson): readonly string[] {
  return Object.keys(pkg.scripts).filter((name) => LIFECYCLE.has(name));
}

export function diffDependencies(
  before: PackageJson,
  after: PackageJson,
): readonly DependencyChange[] {
  const changes: DependencyChange[] = [];
  const both = { ...before.dependencies, ...after.dependencies };

  for (const name of Object.keys(both)) {
    const from = before.dependencies[name];
    const to = after.dependencies[name];
    if (from === undefined) changes.push({ kind: "add", name, ...(to === undefined ? {} : { to }) });
    else if (to === undefined) changes.push({ kind: "remove", name, from });
    else
      changes.push({
        kind: compareRanges(from, to) >= 0 ? "upgrade" : "downgrade",
        name,
        from,
        to,
      });
  }

  return changes;
}

/**
 * Loose range comparison for majors: `^1.2.0` vs `^2.0.0`. Exact ordering of
 * ranges is not decidable; the direction only labels the event, never gates.
 */
function compareRanges(from: string, to: string): number {
  const major = (range: string): number => Number.parseInt(range.replace(/^[^\d]*/, ""), 10);
  const a = major(from);
  const b = major(to);
  if (Number.isNaN(a) || Number.isNaN(b)) return 0;
  return b - a;
}

export interface LockEntry {
  readonly name: string;
  readonly version?: string;
  readonly hasInstallScript?: boolean;
}

/**
 * Read the lockfile's dependency entries from BOTH layouts:
 *
 * - `packages["node_modules/<name>"]` — lockfileVersion 2/3, what every npm
 *   >= 7 writes. `hasInstallScript` lives here. Nested trees repeat the
 *   `node_modules/` marker; the last one names the package.
 * - the flat `dependencies` map — lockfileVersion 1 (and 2, which keeps it
 *   for npm 6 interop).
 *
 * Defect this closes: a v3 lockfile has no flat map, and a parser that read
 * only `dependencies` saw an empty graph on every modern repository — no
 * lifecycle evidence, no package names in an indirect-mutation gate.
 */
export function parsePackageLock(text: string): readonly LockEntry[] {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return [];
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) return [];

  const entries = new Map<string, LockEntry>();

  const packages = (doc as Record<string, unknown>)["packages"];
  if (typeof packages === "object" && packages !== null && !Array.isArray(packages)) {
    for (const [key, value] of Object.entries(packages as Record<string, unknown>)) {
      const marker = key.lastIndexOf("node_modules/");
      if (marker === -1) continue; // "" (the root) and workspace packages
      const name = key.slice(marker + "node_modules/".length);
      if (name === "") continue;
      if (typeof value !== "object" || value === null || Array.isArray(value)) continue;
      const record = value as Record<string, unknown>;
      // A workspace link installs nothing; its target is part of this repo.
      if (record["link"] === true) continue;
      const version = record["version"];
      entries.set(name, {
        name,
        ...(typeof version === "string" ? { version } : {}),
        ...(record["hasInstallScript"] === true ? { hasInstallScript: true } : {}),
      });
    }
  }

  const dependencies = (doc as Record<string, unknown>)["dependencies"];
  if (typeof dependencies === "object" && dependencies !== null && !Array.isArray(dependencies)) {
    for (const [name, value] of Object.entries(dependencies as Record<string, unknown>)) {
      const record =
        typeof value === "object" && value !== null && !Array.isArray(value)
          ? (value as Record<string, unknown>)
          : {};
      const version = record["version"];
      const legacy: LockEntry = {
        name,
        ...(typeof version === "string" ? { version } : {}),
        ...(record["hasInstallScript"] === true ? { hasInstallScript: true } : {}),
      };
      const existing = entries.get(name);
      if (existing === undefined) {
        entries.set(name, legacy);
        continue;
      }
      // The `packages` walk is the authority; the legacy map only fills gaps.
      entries.set(name, {
        ...existing,
        ...(existing.version === undefined && legacy.version !== undefined ? { version: legacy.version } : {}),
        ...(existing.hasInstallScript !== true && legacy.hasInstallScript === true
          ? { hasInstallScript: true }
          : {}),
      });
    }
  }

  return [...entries.values()];
}

/** Same package, different version (or different script flag): the upgrade. */
export interface LockChange {
  readonly name: string;
  readonly from?: string;
  readonly to?: string;
  readonly hasInstallScript?: boolean;
}

export interface LockDiff {
  readonly added: readonly LockEntry[];
  readonly removed: readonly LockEntry[];
  /**
   * Entries whose version moved while the name stayed. A lockfile diff by
   * name alone cannot see `evil@1.0.0 -> evil@9.9.9`, which is the shape a
   * substituted artifact takes.
   */
  readonly changed: readonly LockChange[];
  /**
   * Added or changed entries that run an install script: the npm threat
   * model. An upgrade that GAINS a script is the incident shape exactly.
   */
  readonly scriptRunners: readonly (LockEntry | LockChange)[];
}

export function diffLock(before: readonly LockEntry[], after: readonly LockEntry[]): LockDiff {
  const beforeByName = new Map(before.map((e) => [e.name, e]));
  const afterByName = new Map(after.map((e) => [e.name, e]));
  const added = after.filter((e) => !beforeByName.has(e.name));
  const removed = before.filter((e) => !afterByName.has(e.name));
  const changed: LockChange[] = [];
  for (const entry of after) {
    const prior = beforeByName.get(entry.name);
    if (prior === undefined) continue;
    if (prior.version === entry.version && prior.hasInstallScript === entry.hasInstallScript) {
      continue;
    }
    changed.push({
      name: entry.name,
      ...(prior.version !== undefined ? { from: prior.version } : {}),
      ...(entry.version !== undefined ? { to: entry.version } : {}),
      ...(entry.hasInstallScript === true ? { hasInstallScript: true } : {}),
    });
  }
  return {
    added,
    removed,
    changed,
    scriptRunners: [
      ...added.filter((e) => e.hasInstallScript === true),
      ...changed.filter((c) => c.hasInstallScript === true),
    ],
  };
}

/** Is this spec an exact version rather than a range or a dist-tag? */
export function isExactRange(spec: string): boolean {
  return /^\d+\.\d+\.\d+(-[\w.-]+)?(\+[\w.-]+)?$/.test(spec.trim());
}

/** Dist-tags and the bare-name form float by definition. */
export function isFloatingSpec(spec: string): boolean {
  const trimmed = spec.trim();
  return trimmed === "" || trimmed === "*" || trimmed === "latest" || trimmed === "next";
}
