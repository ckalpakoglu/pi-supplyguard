/**
 * The protected identity corpus (SPEC 12.1, 12.6).
 *
 * THIS IS NOT AN ALLOW-LIST, and the distinction is the whole design. The
 * corpus names identities worth IMPERSONATING; a module that is absent from it
 * is not untrusted, it is simply not something a typo could be aimed at.
 * Reading it the other way round would turn a similarity analyser into a
 * package whitelist that blocks ordinary development.
 *
 * With no corpus, similarity analysis is DISABLED rather than guessed
 * (SPEC 12.6). SupplyGuard does not invent ownership relationships: it has no
 * way to know that `github.com/foo/bar` is the "real" bar, and a tool that
 * guessed would produce confident nonsense about who owns what.
 */

import { readFile } from "node:fs/promises";

import type { Profile } from "./profiles.ts";
import { isEmptyDocument, parseYaml } from "./yaml.ts";

/** SPEC 12.4 -- how wide the net is, per profile. */
export const SIMILARITY_THRESHOLDS = {
  standard: 0.08,
  hardened: 0.15,
  paranoid: 0.25,
} as const satisfies Record<Profile, number>;

export function similarityThreshold(profile: Profile): number {
  return SIMILARITY_THRESHOLDS[profile];
}

export interface ProtectedModule {
  readonly module: string;
  readonly repository?: string;
}

/** Protected identities for one ecosystem, keyed by the adapter's id. */
export interface EcosystemCorpus {
  readonly modules: readonly ProtectedModule[];
  readonly owners: readonly string[];
}

export interface TrustCorpus {
  readonly ecosystems: Readonly<Record<string, EcosystemCorpus>>;
  /** True when nothing was loaded: analysis is off, not permissive. */
  readonly empty: boolean;
  /** Non-secret notes about the files that were read. */
  readonly warnings: readonly string[];
  readonly sources: readonly string[];
}

export const EMPTY_CORPUS: TrustCorpus = Object.freeze({
  ecosystems: Object.freeze({}),
  empty: true,
  warnings: Object.freeze([]) as readonly string[],
  sources: Object.freeze([]) as readonly string[],
});

/** A corpus is small metadata; anything larger is not one. */
const MAX_TRUST_BYTES = 2 * 1024 * 1024;
const MAX_ENTRIES_PER_ECOSYSTEM = 5_000;

export function countIdentities(corpus: TrustCorpus): number {
  return Object.values(corpus.ecosystems).reduce(
    (total, entry) => total + entry.modules.length + entry.owners.length,
    0,
  );
}

/**
 * Interpret an untrusted parsed document.
 *
 * Unknown shapes are dropped with a warning rather than guessed at: a corpus
 * that silently half-loaded would disable protection for exactly the identities
 * whose entries were malformed.
 */
export function parseTrustDocument(raw: unknown): {
  readonly ecosystems: Record<string, EcosystemCorpus>;
  readonly warnings: readonly string[];
} {
  const warnings: string[] = [];
  if (isEmptyDocument(raw)) return { ecosystems: {}, warnings };

  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ecosystems: {}, warnings: ["trust corpus root is not a mapping; ignored."] };
  }

  const protectedSection = (raw as Record<string, unknown>)["protected"];
  if (protectedSection === undefined) {
    return { ecosystems: {}, warnings: [`trust corpus has no "protected" section; ignored.`] };
  }
  if (
    typeof protectedSection !== "object" ||
    protectedSection === null ||
    Array.isArray(protectedSection)
  ) {
    return { ecosystems: {}, warnings: [`"protected" is not a mapping; ignored.`] };
  }

  const ecosystems: Record<string, EcosystemCorpus> = {};

  for (const [ecosystem, value] of Object.entries(protectedSection as Record<string, unknown>)) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      warnings.push(`"protected.${ecosystem}" is not a mapping; ignored.`);
      continue;
    }

    const section = value as Record<string, unknown>;
    const modules: ProtectedModule[] = [];
    const owners: string[] = [];

    const rawModules = section["modules"];
    if (Array.isArray(rawModules)) {
      for (const entry of rawModules.slice(0, MAX_ENTRIES_PER_ECOSYSTEM)) {
        const parsed = parseModuleEntry(entry);
        if (parsed === undefined) {
          warnings.push(`"protected.${ecosystem}.modules" has an unreadable entry; ignored.`);
          continue;
        }
        modules.push(parsed);
      }
    } else if (rawModules !== undefined) {
      warnings.push(`"protected.${ecosystem}.modules" is not a list; ignored.`);
    }

    const rawOwners = section["owners"];
    if (Array.isArray(rawOwners)) {
      for (const entry of rawOwners.slice(0, MAX_ENTRIES_PER_ECOSYSTEM)) {
        if (typeof entry === "string" && entry.trim() !== "") owners.push(entry.trim());
        else warnings.push(`"protected.${ecosystem}.owners" has an unreadable entry; ignored.`);
      }
    } else if (rawOwners !== undefined) {
      warnings.push(`"protected.${ecosystem}.owners" is not a list; ignored.`);
    }

    if (modules.length > 0 || owners.length > 0) {
      ecosystems[ecosystem] = { modules, owners };
    }
  }

  return { ecosystems, warnings };
}

function parseModuleEntry(entry: unknown): ProtectedModule | undefined {
  if (typeof entry === "string") {
    return entry.trim() === "" ? undefined : { module: entry.trim() };
  }
  if (typeof entry !== "object" || entry === null || Array.isArray(entry)) return undefined;

  const record = entry as Record<string, unknown>;
  const module = record["module"];
  if (typeof module !== "string" || module.trim() === "") return undefined;

  const repository = record["repository"];
  return {
    module: module.trim(),
    ...(typeof repository === "string" && repository.trim() !== ""
      ? { repository: repository.trim() }
      : {}),
  };
}

/**
 * Load and merge the global and project corpora.
 *
 * Both layers ADD identities. Unlike configuration there is no tightening
 * question here: a longer list of things worth protecting is never a weakening,
 * and a project cannot remove an identity the workstation wants protected.
 */
export async function loadTrustCorpus(paths: readonly string[]): Promise<TrustCorpus> {
  const ecosystems: Record<string, { modules: ProtectedModule[]; owners: string[] }> = {};
  const warnings: string[] = [];
  const sources: string[] = [];

  for (const path of paths) {
    let text: string;
    try {
      text = await readFile(path, "utf8");
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "ENOENT" && code !== "ENOTDIR") {
        warnings.push(`${path}: could not be read (${code ?? "unknown error"}); ignored.`);
      }
      continue;
    }

    if (Buffer.byteLength(text, "utf8") > MAX_TRUST_BYTES) {
      warnings.push(`${path}: larger than a trust corpus plausibly is; ignored.`);
      continue;
    }

    const parsed = parseYaml(text);
    if (!parsed.ok) {
      warnings.push(`${path}: could not be parsed (${parsed.error}); ignored.`);
      continue;
    }

    const interpreted = parseTrustDocument(parsed.value);
    for (const warning of interpreted.warnings) warnings.push(`${path}: ${warning}`);

    let added = false;
    for (const [ecosystem, corpus] of Object.entries(interpreted.ecosystems)) {
      const target = (ecosystems[ecosystem] ??= { modules: [], owners: [] });
      for (const module of corpus.modules) {
        if (!target.modules.some((existing) => existing.module === module.module)) {
          target.modules.push(module);
          added = true;
        }
      }
      for (const owner of corpus.owners) {
        if (!target.owners.includes(owner)) {
          target.owners.push(owner);
          added = true;
        }
      }
    }
    if (added) sources.push(path);
  }

  const merged: Record<string, EcosystemCorpus> = {};
  for (const [ecosystem, corpus] of Object.entries(ecosystems)) {
    merged[ecosystem] = { modules: corpus.modules, owners: corpus.owners };
  }

  return {
    ecosystems: merged,
    empty: Object.keys(merged).length === 0,
    warnings,
    sources,
  };
}
