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

/** Read the flat `dependencies` map (lockfile v1/v2/v3 all carry it). */
export function parsePackageLock(text: string): readonly LockEntry[] {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return [];
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) return [];
  const dependencies = (doc as Record<string, unknown>)["dependencies"];
  if (typeof dependencies !== "object" || dependencies === null || Array.isArray(dependencies)) {
    return [];
  }

  const entries: LockEntry[] = [];
  for (const [name, value] of Object.entries(dependencies as Record<string, unknown>)) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      entries.push({ name });
      continue;
    }
    const record = value as Record<string, unknown>;
    const version = record["version"];
    entries.push({
      name,
      ...(typeof version === "string" ? { version } : {}),
      ...(record["hasInstallScript"] === true ? { hasInstallScript: true } : {}),
    });
  }
  return entries;
}

export interface LockDiff {
  readonly added: readonly LockEntry[];
  readonly removed: readonly LockEntry[];
  /** Added entries that run an install script: the npm threat model. */
  readonly scriptRunners: readonly LockEntry[];
}

export function diffLock(before: readonly LockEntry[], after: readonly LockEntry[]): LockDiff {
  const beforeByName = new Map(before.map((e) => [e.name, e]));
  const afterByName = new Map(after.map((e) => [e.name, e]));
  const added = after.filter((e) => !beforeByName.has(e.name));
  const removed = before.filter((e) => !afterByName.has(e.name));
  return {
    added,
    removed,
    scriptRunners: added.filter((e) => e.hasInstallScript === true),
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
