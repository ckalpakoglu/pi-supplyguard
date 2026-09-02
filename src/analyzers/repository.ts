/**
 * Component-aware identity analysis (SPEC 12.2, 12.5).
 *
 * A module path is not one string. `github.com/google/uuid` is a host, an owner
 * and a repository, and the attacks aim at different parts of it:
 *
 *     github.com/gooogle/uuid      typo in the OWNER
 *     github.com/google/uuidd      typo in the REPOSITORY
 *     github.com/randomguy/uuid    the real repository name, someone else's account
 *
 * The third has a large edit distance and is the most dangerous of the three,
 * which is why SPEC 12.5 makes it a signal in its own right rather than a
 * distance to be thresholded.
 */

import {
  compareIdentifiers,
  normalizeIdentifier,
  type SimilarityVerdict,
} from "./similarity.ts";

export interface ModuleIdentity {
  readonly host?: string;
  readonly owner?: string;
  readonly repository?: string;
  /** Anything below the repository, e.g. `sdk/v2/client`. */
  readonly subpath?: string;
  /** The path as given, minus any major-version suffix. */
  readonly canonical: string;
}

/** `/v2`, `/v3`, ... is a major-version directory, not a repository name. */
const MAJOR_VERSION_SEGMENT = /^v[2-9]\d*$/;

/**
 * Split a module path into the components SPEC 12.2 compares.
 *
 * Deliberately forgiving: a path that does not look like `host/owner/repo`
 * still yields whatever could be read, and the caller compares only the parts
 * that both sides actually have.
 */
export function parseModuleIdentity(modulePath: string): ModuleIdentity {
  const segments = modulePath.split("/").filter((segment) => segment !== "");

  // A trailing major-version directory belongs to the version, not the name:
  // github.com/foo/bar/v2 is the same repository as github.com/foo/bar.
  const last = segments[segments.length - 1];
  if (segments.length > 1 && last !== undefined && MAJOR_VERSION_SEGMENT.test(last)) {
    segments.pop();
  }

  const canonical = segments.join("/");
  const [host, owner, repository, ...rest] = segments;

  return {
    canonical,
    ...(host === undefined ? {} : { host }),
    ...(owner === undefined ? {} : { owner }),
    ...(repository === undefined ? {} : { repository }),
    ...(rest.length === 0 ? {} : { subpath: rest.join("/") }),
  };
}

export const IDENTITY_SIGNALS = [
  "repository-squat",
  "owner-typo",
  "repository-typo",
  "module-typo",
  "protected-owner-typo",
] as const;

export type IdentitySignal = (typeof IDENTITY_SIGNALS)[number];

export interface IdentityFinding {
  readonly signal: IdentitySignal;
  /** The protected identity this candidate resembles. */
  readonly protectedIdentity: string;
  readonly candidate: string;
  /** Non-secret explanation for the prompt and the audit record. */
  readonly message: string;
  readonly distance?: number;
}

export interface ProtectedIdentity {
  readonly module: string;
  readonly repository?: string;
}

/**
 * Compare one candidate module against one protected identity.
 *
 * Returns at most one finding: the strongest signal wins, because telling an
 * operator three times that `gooogle` is not `google` does not help them decide.
 */
export function compareToProtected(
  candidatePath: string,
  protectedEntry: ProtectedIdentity,
  maxNormalizedDistance: number,
): IdentityFinding | undefined {
  const candidate = parseModuleIdentity(candidatePath);
  const known = parseModuleIdentity(protectedEntry.module);

  // The real thing needs no special case: every comparison below reports
  // "identical", and a path differing only in CASE deliberately still reports,
  // because Go module paths are case-sensitive and `Google/uuid` is not
  // `google/uuid`.
  const sameOwner =
    candidate.owner !== undefined &&
    known.owner !== undefined &&
    normalizeIdentifier(candidate.owner) === normalizeIdentifier(known.owner);

  const sameRepository =
    candidate.repository !== undefined &&
    known.repository !== undefined &&
    normalizeIdentifier(candidate.repository) === normalizeIdentifier(known.repository);

  // SPEC 12.5 -- the protected repository name under a different owner. A
  // distinct signal precisely BECAUSE the edit distance is large: nothing about
  // `random-owner/uuid` looks like a typo, and that is the point.
  if (sameRepository && !sameOwner) {
    return {
      signal: "repository-squat",
      protectedIdentity: protectedEntry.module,
      candidate: candidatePath,
      message:
        `${candidatePath} carries the repository name of the protected identity ` +
        `${protectedEntry.module} under a different owner ` +
        `(${candidate.owner ?? "unknown"} rather than ${known.owner ?? "unknown"}).`,
    };
  }

  if (sameOwner && !sameRepository) {
    const verdict = repositoryVerdict(candidate, known, maxNormalizedDistance);
    if (verdict?.similar === true) {
      return {
        signal: "repository-typo",
        protectedIdentity: protectedEntry.module,
        candidate: candidatePath,
        distance: verdict.distance,
        message:
          `${candidatePath} differs from the protected identity ` +
          `${protectedEntry.module} only in the repository name ` +
          `(${verdict.distance} edit(s)).`,
      };
    }
    return undefined;
  }

  if (!sameOwner && sameRepository) return undefined;

  // Neither component matches exactly: is the owner a near-miss on a repository
  // that also matches? That is the classic typosquat.
  if (
    candidate.owner !== undefined &&
    known.owner !== undefined &&
    candidate.repository !== undefined &&
    known.repository !== undefined
  ) {
    const ownerVerdict = compareIdentifiers(candidate.owner, known.owner, maxNormalizedDistance);
    if (ownerVerdict.similar && sameRepository) {
      return {
        signal: "owner-typo",
        protectedIdentity: protectedEntry.module,
        candidate: candidatePath,
        distance: ownerVerdict.distance,
        message:
          `${candidatePath} has an owner ${ownerVerdict.distance} edit(s) from the ` +
          `protected identity ${protectedEntry.module}.`,
      };
    }
  }

  // Fall back to the whole path: catches `golang.org/x/txt` for
  // `golang.org/x/text`, where the host carries the meaning.
  const whole = compareIdentifiers(candidate.canonical, known.canonical, maxNormalizedDistance);
  if (whole.similar) {
    return {
      signal: "module-typo",
      protectedIdentity: protectedEntry.module,
      candidate: candidatePath,
      distance: whole.distance,
      message:
        `${candidatePath} is ${whole.distance} edit(s) from the protected identity ` +
        `${protectedEntry.module}.`,
    };
  }

  return undefined;
}

function repositoryVerdict(
  candidate: ModuleIdentity,
  known: ModuleIdentity,
  maxNormalizedDistance: number,
): SimilarityVerdict | undefined {
  if (candidate.repository === undefined || known.repository === undefined) return undefined;
  return compareIdentifiers(candidate.repository, known.repository, maxNormalizedDistance);
}

/**
 * Compare a candidate's owner against the list of protected owners.
 *
 * An owner list is broader than a module list: it says "these accounts are
 * worth impersonating", so a near-miss on one is worth reporting even when the
 * repository name means nothing to us.
 */
export function compareToProtectedOwners(
  candidatePath: string,
  owners: readonly string[],
  maxNormalizedDistance: number,
): IdentityFinding | undefined {
  const candidate = parseModuleIdentity(candidatePath);
  if (candidate.owner === undefined) return undefined;

  for (const owner of owners) {
    if (normalizeIdentifier(candidate.owner) === normalizeIdentifier(owner)) return undefined;
  }

  for (const owner of owners) {
    const verdict = compareIdentifiers(candidate.owner, owner, maxNormalizedDistance);
    if (!verdict.similar) continue;
    return {
      signal: "protected-owner-typo",
      protectedIdentity: owner,
      candidate: candidatePath,
      distance: verdict.distance,
      message:
        `${candidatePath} is owned by "${candidate.owner}", ${verdict.distance} edit(s) from ` +
        `the protected owner "${owner}".`,
    };
  }

  return undefined;
}
