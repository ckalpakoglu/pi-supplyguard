/**
 * Go project and vendor model (SPEC 9).
 *
 * Two questions live here:
 *
 * 1. Is this a Go project, and does it vendor its dependencies?
 * 2. Is the vendor tree still consistent with `go.mod`?
 *
 * Question 2 is answered from the FILES rather than from a remembered
 * `dependencyGraphDirty` flag. SPEC 9.4 describes the state machine
 * (mutation -> stale, `go mod vendor` -> current); deriving the same answer
 * from `go.mod` versus `vendor/modules.txt` gives identical semantics without
 * a flag that a restarted session, an out-of-band edit, or a crash could
 * desynchronize from the repository.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { parseGoMod, type GoMod } from "./modfile.ts";

export const GO_MOD = "go.mod";
export const GO_SUM = "go.sum";
export const GO_WORK = "go.work";
export const GO_WORK_SUM = "go.work.sum";
export const VENDOR_MODULES = "vendor/modules.txt";
/** Write-guard prefix for vendored source (see the Go adapter). */
export const VENDOR_PREFIX = "vendor/";

/** SPEC 14.1 -- the Go files whose content SupplyGuard tracks. */
export const GO_SENSITIVE_PATHS: readonly string[] = [
  GO_MOD,
  GO_SUM,
  GO_WORK,
  GO_WORK_SUM,
  VENDOR_MODULES,
];

/** One module recorded in `vendor/modules.txt`. */
export interface VendoredModule {
  readonly path: string;
  readonly version: string;
  /** True when the vendor tree marks the module as an explicit requirement. */
  readonly explicit: boolean;
}

/**
 * Parse `vendor/modules.txt`.
 *
 * Format written by `go mod vendor`:
 *
 *     # github.com/foo/bar v1.2.3
 *     ## explicit; go 1.21
 *     github.com/foo/bar
 *
 * A `# path version` line opens a module; the `## explicit` annotation that
 * may follow marks it as directly required. Package lines are ignored: the
 * unit of trust is the module.
 */
export function parseVendorModules(text: string): readonly VendoredModule[] {
  const modules: VendoredModule[] = [];
  const explicitness: boolean[] = [];

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("##")) {
      // Annotation for the module opened above; `explicit` may be followed by
      // `; go 1.21` and further semicolon-separated markers.
      if (modules.length > 0 && /(^|;|\s)explicit(\s|;|$)/.test(line.slice(2))) {
        explicitness[modules.length - 1] = true;
      }
      continue;
    }
    if (!line.startsWith("#")) continue;

    const words = line.slice(1).trim().split(/\s+/);
    const path = words[0];
    const version = words[1];
    // `# path v1.2.3 => other v1.0.0` records a replace; the effective
    // requirement is what go.mod asks for, so only the left side is compared.
    if (path === undefined || version === undefined || !version.startsWith("v")) continue;

    modules.push({ path, version, explicit: false });
    explicitness.push(false);
  }

  return modules.map((module, index) => ({
    ...module,
    explicit: explicitness[index] ?? false,
  }));
}

export const VENDOR_STATES = ["absent", "current", "stale"] as const;

export type VendorState = (typeof VENDOR_STATES)[number];

export interface GoProject {
  /** True when any Go signal was found (SPEC 9.1). */
  readonly isGoProject: boolean;
  readonly hasGoMod: boolean;
  readonly hasGoWork: boolean;
  readonly hasGoSum: boolean;
  readonly hasVendorTree: boolean;
  readonly vendorState: VendorState;
  /** Non-secret explanations of a `stale` vendor state; empty otherwise. */
  readonly driftReasons: readonly string[];
}

export const NO_GO_PROJECT: GoProject = Object.freeze({
  isGoProject: false,
  hasGoMod: false,
  hasGoWork: false,
  hasGoSum: false,
  hasVendorTree: false,
  vendorState: "absent",
  driftReasons: Object.freeze([]) as readonly string[],
});

/**
 * Compare a parsed `go.mod` against a parsed vendor tree (SPEC 9.4).
 *
 * Two signals mean the tree is stale:
 *
 * - a vendored module pinned at a version `go.mod` no longer requires;
 * - a module the tree marks explicit that `go.mod` no longer requires at all.
 *
 * The reverse -- a requirement absent from the vendor tree -- is NOT drift:
 * `go mod vendor` only vendors modules whose packages are actually imported,
 * so a required-but-unimported module is legitimately missing.
 */
export function vendorDrift(
  mod: GoMod,
  vendored: readonly VendoredModule[],
): readonly string[] {
  const required = new Map(mod.requires.map((r) => [r.path, r.version] as const));
  const replaced = new Set(mod.replaces.map((r) => r.from));
  const reasons: string[] = [];

  for (const module of vendored) {
    // A replace directive redirects the module; `vendor/modules.txt` then
    // records the replacement target's version, which `go.mod` requires does
    // not describe. Comparing those two would be comparing different things.
    if (replaced.has(module.path)) continue;

    const want = required.get(module.path);
    if (want === undefined) {
      if (module.explicit) {
        reasons.push(
          `vendor/modules.txt marks ${module.path} explicit, but go.mod no longer requires it`,
        );
      }
      continue;
    }
    if (want !== module.version) {
      reasons.push(
        `vendor/modules.txt has ${module.path} ${module.version}, go.mod requires ${want}`,
      );
    }
  }

  return reasons;
}

async function readText(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, "utf8");
  } catch {
    return undefined;
  }
}

/**
 * Detect the Go project at `repoRoot` and evaluate its vendor state.
 *
 * `*.go` files are deliberately NOT scanned: SPEC 9.1 lists them as a secondary
 * signal, and walking a repository on every tool call to find one would cost
 * more than it tells us. `go.mod`/`go.work` are the signals that matter for
 * every control SupplyGuard enforces.
 */
export async function detectGoProject(repoRoot: string): Promise<GoProject> {
  const [goModText, goWorkText, goSumText, vendorText] = await Promise.all([
    readText(join(repoRoot, GO_MOD)),
    readText(join(repoRoot, GO_WORK)),
    readText(join(repoRoot, GO_SUM)),
    readText(join(repoRoot, VENDOR_MODULES)),
  ]);

  const hasGoMod = goModText !== undefined;
  const hasGoWork = goWorkText !== undefined;
  const hasVendorTree = vendorText !== undefined;

  if (!hasGoMod && !hasGoWork && !hasVendorTree) return NO_GO_PROJECT;

  const driftReasons =
    hasVendorTree && hasGoMod
      ? vendorDrift(parseGoMod(goModText), parseVendorModules(vendorText))
      : [];

  return {
    isGoProject: true,
    hasGoMod,
    hasGoWork,
    hasGoSum: goSumText !== undefined,
    hasVendorTree,
    vendorState: !hasVendorTree ? "absent" : driftReasons.length > 0 ? "stale" : "current",
    driftReasons,
  };
}
