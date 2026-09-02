/**
 * String similarity for identity analysis (SPEC 12.3, 22).
 *
 * Implemented here rather than pulled in: SPEC 22 asks for exactly that, and a
 * dependency-minimising tool reaching for a levenshtein package to compare two
 * short strings would be a poor advertisement for itself.
 *
 * The variant is the RESTRICTED Damerau-Levenshtein (optimal string alignment):
 * insertions, deletions, substitutions and transpositions of ADJACENT
 * characters. The unrestricted algorithm additionally allows a transposed pair
 * to be edited again afterwards, which costs more to compute and describes a
 * typo nobody makes. Adjacent transposition -- `recieve`, `stipe` for `stripe`
 * -- is the whole reason a plain Levenshtein distance is not enough here.
 */

/** Longest input compared; identities are short and this bounds the work. */
const MAX_LENGTH = 256;

/**
 * Restricted Damerau-Levenshtein distance.
 *
 * Returns the number of single-character edits between `a` and `b`, counting an
 * adjacent transposition as one edit rather than two.
 */
export function damerauLevenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length > MAX_LENGTH || b.length > MAX_LENGTH) {
    return Math.max(a.length, b.length);
  }
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  // Three rows are enough for the restricted variant: the current row, the
  // previous one, and the one before it for the transposition case.
  let twoBack: number[] = [];
  let previous: number[] = Array.from({ length: b.length + 1 }, (_unused, index) => index);
  let current: number[] = new Array<number>(b.length + 1).fill(0);

  for (let i = 1; i <= a.length; i += 1) {
    current[0] = i;
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let best = Math.min(
        (current[j - 1] ?? 0) + 1, // insertion
        (previous[j] ?? 0) + 1, // deletion
        (previous[j - 1] ?? 0) + cost, // substitution
      );

      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        best = Math.min(best, (twoBack[j - 2] ?? 0) + 1); // transposition
      }
      current[j] = best;
    }
    twoBack = previous;
    previous = current;
    current = new Array<number>(b.length + 1).fill(0);
  }

  return previous[b.length] ?? 0;
}

/** Distance as a fraction of the longer string. 0 is identical, 1 is nothing alike. */
export function normalizedDistance(a: string, b: string): number {
  const longest = Math.max(a.length, b.length);
  if (longest === 0) return 0;
  return damerauLevenshtein(a, b) / longest;
}

/**
 * Identifiers at or below this length use an ABSOLUTE distance instead.
 *
 * SPEC 12.3 asks for this split, and the reason is arithmetic: one edit in a
 * four-character name is a normalized distance of 0.25, which no sane threshold
 * would catch, yet `gorm` and `gonm` are exactly the pair that matters.
 */
export const SHORT_IDENTIFIER_LENGTH = 5;

/** One edit is enough to flag a short identifier. */
export const SHORT_IDENTIFIER_MAX_DISTANCE = 1;

/**
 * Fold away the differences a squatter relies on the eye missing.
 *
 * Separators and case carry no meaning in a package name -- `go-redis`,
 * `go_redis` and `goredis` read as the same word -- so they are removed before
 * comparison. Without this, a separator swap costs one edit in a long name and
 * lands under every threshold.
 */
export function normalizeIdentifier(value: string): string {
  return value.toLowerCase().replace(/[-_.]/g, "");
}

export interface SimilarityVerdict {
  /** True when the pair is close enough to report at this threshold. */
  readonly similar: boolean;
  readonly distance: number;
  readonly normalized: number;
  /** Why it matched: useful in the finding message, never a secret. */
  readonly signal: "identical" | "short-identifier" | "normalized-distance" | "separator-variant";
}

/**
 * Compare two identifiers at a profile's sensitivity.
 *
 * `maxNormalizedDistance` comes from the profile (SPEC 12.4): 0.08, 0.15, 0.25.
 * The profile decides how WIDE the net is; what happens to a catch is policy.
 */
export function compareIdentifiers(
  candidate: string,
  protectedName: string,
  maxNormalizedDistance: number,
): SimilarityVerdict {
  if (candidate === protectedName) {
    return { similar: false, distance: 0, normalized: 0, signal: "identical" };
  }

  const a = normalizeIdentifier(candidate);
  const b = normalizeIdentifier(protectedName);

  // Same word, different punctuation: `go-redis` vs `goredis`.
  if (a === b) {
    return { similar: true, distance: 0, normalized: 0, signal: "separator-variant" };
  }

  const distance = damerauLevenshtein(a, b);
  const normalized = distance / Math.max(a.length, b.length, 1);

  if (Math.min(a.length, b.length) <= SHORT_IDENTIFIER_LENGTH) {
    return {
      similar: distance <= SHORT_IDENTIFIER_MAX_DISTANCE,
      distance,
      normalized,
      signal: "short-identifier",
    };
  }

  return {
    similar: normalized <= maxNormalizedDistance,
    distance,
    normalized,
    signal: "normalized-distance",
  };
}
