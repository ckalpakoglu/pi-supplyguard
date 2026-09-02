/**
 * `go.mod` / `go.sum` parsing and semantic classification (SPEC 10.5, 14).
 *
 * Pure functions: no filesystem, no execution. The reconciliation layer
 * (manifest.ts) feeds before/after text into `parseGoMod` / `parseGoSum` and
 * turns `diffGoMod` / `diffGoSum` results into normalized events through the
 * adapter. Everything here is deliberately forgiving about syntax it does not
 * understand -- a line that cannot be parsed is skipped, because the HASH
 * comparison is what detects the mutation; the parser only classifies it.
 */

/**
 * Semantic version comparison, Go-flavoured.
 *
 * Understands:
 * - release versions: `v1.2.3`, `v1.2.3-pre`;
 * - pseudo-versions: `v0.0.0-20230101120000-abcdef123456` and the
 *   `v1.2.3-pre.0.20230101120000-abcdef` form;
 * - major-version subdirectory modules (`/v2`) -- the suffix lives in the
 *   module PATH, but a version whose major differs from the path's major is a
 *   different dependency, not an upgrade, so it never reaches comparison.
 *
 * Returns -1 / 0 / 1. Unparseable versions compare as "changed" (never equal
 * unless string-identical), which is conservative: an unreadable diff is a
 * mutation, never silence.
 */
export function compareVersions(a: string, b: string): number {
  if (a === b) return 0;
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (pa === undefined || pb === undefined) return a < b ? -1 : 1;

  // Base semver first.
  const ma = pa.numeric;
  const mb = pb.numeric;
  if (ma[0] !== mb[0]) return ma[0] < mb[0] ? -1 : 1;
  if (ma[1] !== mb[1]) return ma[1] < mb[1] ? -1 : 1;
  if (ma[2] !== mb[2]) return ma[2] < mb[2] ? -1 : 1;

  // A pre-release sorts BEFORE its release (`v1.2.3-pre` < `v1.2.3`).
  if (pa.prerelease === undefined && pb.prerelease === undefined) {
    return comparePseudo(pa, pb);
  }
  if (pa.prerelease === undefined) return 1;
  if (pb.prerelease === undefined) return -1;

  const cmp = comparePrerelease(pa.prerelease, pb.prerelease);
  return cmp !== 0 ? cmp : comparePseudo(pa, pb);
}

interface ParsedVersion {
  readonly numeric: readonly [number, number, number];
  readonly prerelease?: string;
  /** Pseudo-version timestamp, when present. */
  readonly pseudoTimestamp?: string;
}

function parseVersion(version: string): ParsedVersion | undefined {
  // Canonical pseudo-version: vX.Y.Z(-pre).0.yyyymmddhhmmss-hash. The VERSION_RE
  // above cannot express "the prerelease ends with .0.<ts>-<hash>", so peel the
  // pseudo suffix off first.
  const pseudo = /^(v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\.(0\.\d{14}-[0-9A-Za-z]{12,})$/.exec(
    version,
  );
  if (pseudo !== null) {
    const base = parsePlain(pseudo[1] ?? "");
    if (base !== undefined) {
      const stamp = /(?:^|\.)0\.(\d{14})-/.exec(pseudo[2] ?? "")?.[1];
      return stamp === undefined ? base : { ...base, pseudoTimestamp: stamp };
    }
  }
  // A bare pseudo-version (`v0.0.0-<timestamp>-<hash>`) parses as a plain
  // version whose prerelease is the timestamp, and fixed-width timestamps
  // order correctly as strings -- so it needs no separate case.
  return parsePlain(version);
}

function parsePlain(version: string): ParsedVersion | undefined {
  const match = /^v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(
    version,
  );
  if (match === null) return undefined;
  return {
    numeric: [Number(match[1]), Number(match[2]), Number(match[3])],
    ...(match[4] === undefined ? {} : { prerelease: match[4] }),
  };
}

/** Identical base + prerelease: the newer pseudo-timestamp wins. */
function comparePseudo(a: ParsedVersion, b: ParsedVersion): number {
  if (a.pseudoTimestamp !== undefined && b.pseudoTimestamp !== undefined) {
    return a.pseudoTimestamp < b.pseudoTimestamp ? -1 : a.pseudoTimestamp > b.pseudoTimestamp ? 1 : 0;
  }
  if (a.pseudoTimestamp !== undefined) return -1;
  if (b.pseudoTimestamp !== undefined) return 1;
  return 0;
}

function comparePrerelease(a: string, b: string): number {
  const as = a.split(".");
  const bs = b.split(".");
  for (let i = 0; i < Math.max(as.length, bs.length); i += 1) {
    const x = as[i];
    const y = bs[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    const nx = Number(x);
    const ny = Number(y);
    if (Number.isFinite(nx) && Number.isFinite(ny) && nx !== ny) return nx < ny ? -1 : 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

/** Require directive: `path v1.2.3` optionally suffixed `// indirect`. */
export interface GoRequire {
  readonly path: string;
  readonly version: string;
  readonly indirect: boolean;
}

/** Replace directive: `old [vX] => new [vY]`; local targets have no version. */
export interface GoReplace {
  readonly from: string;
  readonly to: string;
  /** Present only for remote targets. */
  readonly version?: string;
}

export interface GoExclude {
  readonly path: string;
  readonly version: string;
}

/** Retract versions: single or range. Kept as raw text; not diffed further. */
export interface GoRetract {
  readonly version: string;
}

export interface GoMod {
  readonly module?: string;
  readonly go?: string;
  readonly toolchain?: string;
  readonly requires: readonly GoRequire[];
  readonly replaces: readonly GoReplace[];
  readonly excludes: readonly GoExclude[];
  readonly retracts: readonly GoRetract[];
  /** Lines the parser could not attribute; never empty on a hash-changing diff. */
  readonly unparsed: readonly string[];
}

const EMPTY_GOMOD: GoMod = Object.freeze({
  requires: Object.freeze([]),
  replaces: Object.freeze([]),
  excludes: Object.freeze([]),
  retracts: Object.freeze([]),
  unparsed: Object.freeze([]),
});

interface SplitLine {
  /** The directive text, comment removed. */
  readonly code: string;
  /** The comment body, without the leading `//`. Empty when there is none. */
  readonly comment: string;
}

function splitComment(line: string): SplitLine {
  // A `//` inside a quoted string is not a comment; go.mod quotes only strings,
  // and a naive split is fine for the directive forms we model (no `//` inside
  // module paths). Paths cannot contain `//`.
  //
  // The comment is returned rather than discarded because `// indirect` is
  // load-bearing: it is the only marker distinguishing a direct requirement
  // from one Go added on a dependency's behalf.
  const at = line.indexOf("//");
  return at === -1
    ? { code: line, comment: "" }
    : { code: line.slice(0, at), comment: line.slice(at + 2) };
}

/** Is a replace target a local path rather than a remote module? */
export function isLocalReplaceTarget(target: string): boolean {
  return (
    target === "." ||
    target === ".." ||
    target.startsWith("./") ||
    target.startsWith("../") ||
    target.startsWith("/") ||
    /^[A-Za-z]:[\\/]/.test(target)
  );
}

/**
 * Parse a `go.mod` document.
 *
 * Handles inline and block forms of `require` / `replace` / `exclude` /
 * `retract`, the `+insecure`/`+indirect` suffixes (only `indirect` is defined
 * by Go; `insecure` on a replace is historical), and `// indirect` markers.
 * Anything else lands in `unparsed` -- visible, never guessed.
 */
export function parseGoMod(text: string): GoMod {
  const module: { value?: string } = {};
  const go: { value?: string } = {};
  const toolchain: { value?: string } = {};
  const requires: GoRequire[] = [];
  const replaces: GoReplace[] = [];
  const excludes: GoExclude[] = [];
  const retracts: GoRetract[] = [];
  const unparsed: string[] = [];

  let block: "require" | "replace" | "exclude" | "retract" | undefined;

  for (const rawLine of text.split(/\r?\n/)) {
    const split = splitComment(rawLine);
    const line = split.code.trim();
    const comment = split.comment;
    if (line === "") continue;

    if (block !== undefined) {
      if (line === ")") {
        block = undefined;
        continue;
      }
      feedDirective(block, line, comment, { requires, replaces, excludes, retracts, unparsed });
      continue;
    }

    const open = /^(require|replace|exclude|retract)\s*\($/.exec(line);
    if (open !== null) {
      block = open[1] as typeof block;
      continue;
    }

    const head = /^(\w+)\s*(.*)$/.exec(line);
    const keyword = head?.[1];
    const rest = head?.[2]?.trim() ?? "";
    if (keyword === undefined) continue;

    if (keyword === "module" && rest !== "") {
      module.value = rest.replace(/^"|"$/g, "");
      continue;
    }
    if (keyword === "go" && rest !== "") {
      go.value = rest;
      continue;
    }
    if (keyword === "toolchain" && rest !== "") {
      toolchain.value = rest;
      continue;
    }
    if (
      (keyword === "require" || keyword === "replace" || keyword === "exclude" || keyword === "retract") &&
      rest !== ""
    ) {
      feedDirective(keyword, rest, comment, { requires, replaces, excludes, retracts, unparsed });
      continue;
    }
    unparsed.push(line);
  }

  return {
    ...(module.value === undefined ? {} : { module: module.value }),
    ...(go.value === undefined ? {} : { go: go.value }),
    ...(toolchain.value === undefined ? {} : { toolchain: toolchain.value }),
    requires,
    replaces,
    excludes,
    retracts,
    unparsed,
  };
}

interface DirectiveSinks {
  readonly requires: GoRequire[];
  readonly replaces: GoReplace[];
  readonly excludes: GoExclude[];
  readonly retracts: GoRetract[];
  readonly unparsed: string[];
}

function feedDirective(
  kind: "require" | "replace" | "exclude" | "retract",
  line: string,
  comment: string,
  sinks: DirectiveSinks,
): void {
  const words = line.split(/\s+/);
  if (kind === "require") {
    const path = words[0];
    const version = words[1];
    if (path === undefined || version === undefined) {
      sinks.unparsed.push(line);
      return;
    }
    sinks.requires.push({ path, version, indirect: isIndirect(line, comment) });
    return;
  }
  if (kind === "exclude") {
    const path = words[0];
    const version = words[1];
    if (path === undefined || version === undefined) {
      sinks.unparsed.push(line);
      return;
    }
    sinks.excludes.push({ path, version });
    return;
  }
  if (kind === "retract") {
    // A range is written `[v1.0.0, v1.0.2]` -- one directive containing a
    // space, so it must be read from the whole line, not from `words[0]`.
    // Whitespace is normalized away so reformatting is not a change.
    const compact = line.replace(/\s+/g, "");
    if (/^v\S+$/.test(compact) || /^\[v[^,\]]+,v[^,\]]+\]$/.test(compact)) {
      sinks.retracts.push({ version: compact });
      return;
    }
    sinks.unparsed.push(line);
    return;
  }
  // replace: `from [vX] => to [vY]`
  const arrow = line.indexOf("=>");
  if (arrow === -1) {
    sinks.unparsed.push(line);
    return;
  }
  const left = line.slice(0, arrow).trim().split(/\s+/);
  const right = line.slice(arrow + 2).trim().split(/\s+/);
  const from = left[0];
  const to = right[0];
  if (from === undefined || to === undefined || to === "") {
    sinks.unparsed.push(line);
    return;
  }
  sinks.replaces.push({
    from,
    to,
    ...(right[1] === undefined ? {} : { version: right[1] }),
  });
}

function isIndirect(line: string, comment: string): boolean {
  return /\bindirect\b/.test(comment) || /\+indirect\b/.test(line);
}

/** A single semantic change between two go.mod documents. */
export type GoModChange =
  | { readonly kind: "add"; readonly require: GoRequire }
  | { readonly kind: "upgrade"; readonly require: GoRequire; readonly from: string }
  | { readonly kind: "downgrade"; readonly require: GoRequire; readonly from: string }
  | { readonly kind: "remove"; readonly path: string; readonly fromVersion: string }
  | { readonly kind: "indirect-flag"; readonly require: GoRequire; readonly wasIndirect: boolean }
  | { readonly kind: "replace-add"; readonly replace: GoReplace }
  | { readonly kind: "replace-change"; readonly replace: GoReplace; readonly fromReplace: GoReplace }
  | { readonly kind: "replace-remove"; readonly from: string }
  | { readonly kind: "exclude-add"; readonly exclude: GoExclude }
  | { readonly kind: "exclude-remove"; readonly path: string }
  | { readonly kind: "other"; readonly summary: string };

export interface GoModDiff {
  readonly changes: readonly GoModChange[];
  /** True when require/replace/exclude/retract structure changed at all. */
  readonly dependencyGraphChanged: boolean;
  /** True when module/go/toolchain or unparsed lines changed. */
  readonly metadataChanged: boolean;
}

/**
 * Semantically diff two parsed `go.mod` documents.
 *
 * A `module` directive change, a `go`/`toolchain` version change, or a change
 * in `unparsed` lines yields an `other` change: the hash said the file changed,
 * and honest classification is better than silence. Such changes do NOT mark
 * the dependency graph dirty on their own.
 */
export function diffGoMod(before: GoMod, after: GoMod): GoModDiff {
  const changes: GoModChange[] = [];

  const beforeReqs = new Map(before.requires.map((r) => [r.path, r] as const));
  const afterReqs = new Map(after.requires.map((r) => [r.path, r] as const));

  for (const [path, req] of afterReqs) {
    const old = beforeReqs.get(path);
    if (old === undefined) {
      changes.push({ kind: "add", require: req });
      continue;
    }
    if (old.version !== req.version) {
      // compareVersions(old, new) < 0 means the NEW version sorts later.
      const cmp = compareVersions(old.version, req.version);
      if (cmp < 0) changes.push({ kind: "upgrade", require: req, from: old.version });
      else if (cmp > 0) changes.push({ kind: "downgrade", require: req, from: old.version });
      else changes.push({ kind: "other", summary: `version text for ${path} changed (${old.version} -> ${req.version})` });
    }
    if (old.indirect !== req.indirect) {
      changes.push({ kind: "indirect-flag", require: req, wasIndirect: old.indirect });
    }
  }
  for (const [path, req] of beforeReqs) {
    if (!afterReqs.has(path)) {
      changes.push({ kind: "remove", path, fromVersion: req.version });
    }
  }

  const beforeRepl = new Map(before.replaces.map((r) => [r.from, r] as const));
  const afterRepl = new Map(after.replaces.map((r) => [r.from, r] as const));
  for (const [from, replace] of afterRepl) {
    const old = beforeRepl.get(from);
    if (old === undefined) {
      changes.push({ kind: "replace-add", replace });
      continue;
    }
    if (old.to !== replace.to || old.version !== replace.version) {
      changes.push({ kind: "replace-change", replace, fromReplace: old });
    }
  }
  for (const from of beforeRepl.keys()) {
    if (!afterRepl.has(from)) changes.push({ kind: "replace-remove", from });
  }

  const beforeExcl = new Set(before.excludes.map((e) => `${e.path}@${e.version}`));
  const afterExcl = new Set(after.excludes.map((e) => `${e.path}@${e.version}`));
  for (const key of afterExcl) {
    if (!beforeExcl.has(key)) {
      const [path, version] = splitAtLastAt(key);
      changes.push({ kind: "exclude-add", exclude: { path: path ?? key, version: version ?? "" } });
    }
  }
  for (const key of beforeExcl) {
    if (!afterExcl.has(key)) {
      const [path] = splitAtLastAt(key);
      changes.push({ kind: "exclude-remove", path: path ?? key });
    }
  }

  if (before.module !== after.module) {
    changes.push({ kind: "other", summary: `module path changed (${before.module ?? "none"} -> ${after.module ?? "none"})` });
  }
  if (before.go !== after.go) {
    changes.push({ kind: "other", summary: `go directive changed (${before.go ?? "none"} -> ${after.go ?? "none"})` });
  }
  if (before.toolchain !== after.toolchain) {
    changes.push({ kind: "other", summary: `toolchain directive changed` });
  }
  if (before.retracts.length !== after.retracts.length) {
    changes.push({ kind: "other", summary: `retract directives changed` });
  } else if (
    before.retracts.some((r, i) => r.version !== after.retracts[i]?.version)
  ) {
    changes.push({ kind: "other", summary: `retract directives changed` });
  }
  const beforeUnk = before.unparsed.join("\n");
  const afterUnk = after.unparsed.join("\n");
  if (beforeUnk !== afterUnk) {
    changes.push({ kind: "other", summary: "unrecognized go.mod structure changed" });
  }

  const graphKinds = new Set(["add", "upgrade", "downgrade", "remove", "replace-add", "replace-change", "replace-remove", "exclude-add", "exclude-remove", "indirect-flag"]);
  const dependencyGraphChanged = changes.some((c) => graphKinds.has(c.kind));

  return {
    changes,
    dependencyGraphChanged,
    metadataChanged: changes.some((c) => c.kind === "other"),
  };
}

function splitAtLastAt(key: string): [string | undefined, string | undefined] {
  const at = key.lastIndexOf("@");
  if (at === -1) return [undefined, undefined];
  return [key.slice(0, at), key.slice(at + 1)];
}

/** One `go.sum` line: `module version[/go.mod] hash`. */
export interface GoSumEntry {
  readonly line: string;
  readonly path: string;
  readonly version: string;
  /** True for the `/go.mod`-suffixed hash line. */
  readonly goModHash: boolean;
}

export function parseGoSum(text: string): readonly GoSumEntry[] {
  const entries: GoSumEntry[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "") continue;
    const words = line.split(/\s+/);
    const path = words[0];
    const version = words[1];
    if (path === undefined || version === undefined || words.length < 3) {
      entries.push({ line, path: line, version: "", goModHash: false });
      continue;
    }
    entries.push({
      line,
      path,
      version: version.replace(/\/go\.mod$/, ""),
      goModHash: version.endsWith("/go.mod"),
    });
  }
  return entries;
}

export interface GoSumDiff {
  readonly added: readonly GoSumEntry[];
  readonly removed: readonly GoSumEntry[];
}

/** Set-based diff of go.sum lines; a changed hash is remove+add of a line. */
export function diffGoSum(before: readonly GoSumEntry[], after: readonly GoSumEntry[]): GoSumDiff {
  const beforeLines = new Set(before.map((e) => e.line));
  const afterLines = new Set(after.map((e) => e.line));
  const added = after.filter((e) => !beforeLines.has(e.line));
  const removed = before.filter((e) => !afterLines.has(e.line));
  return { added, removed };
}
