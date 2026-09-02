/**
 * Manifest integrity snapshots (SPEC 14).
 *
 * Tool-call interception is not a filesystem boundary. An agent that cannot run
 * `go get` can still rewrite `go.mod` with `sed`, Python, or a generated
 * script, and the command gate would see nothing. So SupplyGuard also watches
 * the files themselves: it snapshots the sensitive set before a tool runs and
 * compares that snapshot on the next tool call. A change nobody asked for
 * becomes a normalized event and is gated like any other trust decision.
 *
 * ECOSYSTEM-AGNOSTIC: this module knows about paths, bytes and hashes. Which
 * paths are sensitive, and what a change to one MEANS, are adapter questions
 * (SPEC 7).
 */

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";

/**
 * Largest file whose CONTENT is retained for semantic diffing.
 *
 * Beyond this only the hash is kept: a change is still detected, but it cannot
 * be classified, which the reconciler reports honestly rather than ignoring.
 * `go.sum` in a very large repository is the realistic upper bound here.
 */
export const MAX_TRACKED_BYTES = 4 * 1024 * 1024;

export interface ManifestFile {
  /** SHA-256 of the file bytes, hex. */
  readonly hash: string;
  readonly bytes: number;
  /** Absent when the file exceeded `MAX_TRACKED_BYTES`. */
  readonly text?: string;
}

/** A file that is absent is recorded as `null`, never omitted: "absent" is a
 * fact about the repository, and a missing key would be indistinguishable from
 * a path nobody watched. */
export type ManifestSnapshot = Readonly<Record<string, ManifestFile | null>>;

export const EMPTY_SNAPSHOT: ManifestSnapshot = Object.freeze({});

/** One observed before/after change to a watched file. */
export interface FileMutation {
  /** Repository-relative path, POSIX separators. */
  readonly path: string;
  /** Content before the change; absent if the file did not exist or was too large. */
  readonly before?: string;
  /** Content after the change; absent if the file was deleted or is too large. */
  readonly after?: string;
  readonly existedBefore: boolean;
  readonly existsAfter: boolean;
  /**
   * False when the change is known (hashes differ) but the content was not
   * retained. A consumer must treat this as "changed, unclassifiable" -- never
   * as "unchanged".
   */
  readonly contentAvailable: boolean;
}

function sha256(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Reject a declared path that escapes the repository.
 *
 * Adapter-declared paths are code, not user input, but a snapshot reader that
 * silently followed `../../etc/shadow` would be a poor primitive to build a
 * security control on.
 */
function safeJoin(repoRoot: string, relPath: string): string | undefined {
  if (isAbsolute(relPath)) return undefined;
  const full = resolve(repoRoot, relPath);
  const back = relative(resolve(repoRoot), full);
  if (back === "" || back.startsWith("..") || isAbsolute(back)) return undefined;
  return full;
}

/**
 * Read the current state of every watched path.
 *
 * An unreadable file (permissions, a directory in its place) is recorded as
 * absent: SupplyGuard reports what it could observe and never invents content.
 * The resulting "absent -> present" transition on the next successful read is
 * itself reported as a mutation, which is the conservative direction.
 */
export async function readManifestSnapshot(
  repoRoot: string,
  paths: readonly string[],
): Promise<ManifestSnapshot> {
  const snapshot: Record<string, ManifestFile | null> = {};

  await Promise.all(
    paths.map(async (relPath) => {
      const full = safeJoin(repoRoot, relPath);
      if (full === undefined) return;

      try {
        const data = await readFile(full);
        snapshot[relPath] =
          data.byteLength > MAX_TRACKED_BYTES
            ? { hash: sha256(data), bytes: data.byteLength }
            : { hash: sha256(data), bytes: data.byteLength, text: data.toString("utf8") };
      } catch {
        snapshot[relPath] = null;
      }
    }),
  );

  return snapshot;
}

/**
 * Compare two snapshots.
 *
 * A path present in only one snapshot is compared against "absent", so adding
 * a watched path mid-session cannot hide a change. Paths are returned in
 * lexical order so audit output is stable.
 */
export function diffManifestSnapshot(
  before: ManifestSnapshot,
  after: ManifestSnapshot,
): readonly FileMutation[] {
  const mutations: FileMutation[] = [];

  for (const path of [...new Set([...Object.keys(before), ...Object.keys(after)])].sort()) {
    const was = before[path] ?? null;
    const now = after[path] ?? null;
    if (was === null && now === null) continue;
    if (was !== null && now !== null && was.hash === now.hash) continue;

    mutations.push({
      path,
      ...(was?.text === undefined ? {} : { before: was.text }),
      ...(now?.text === undefined ? {} : { after: now.text }),
      existedBefore: was !== null,
      existsAfter: now !== null,
      // Content is available when every side that exists retained its text.
      contentAvailable:
        (was === null || was.text !== undefined) && (now === null || now.text !== undefined),
    });
  }

  return mutations;
}

/** Short non-secret description of a mutation, for audit notes. */
export function describeMutation(mutation: FileMutation): string {
  if (!mutation.existedBefore) return `${mutation.path} was created`;
  if (!mutation.existsAfter) return `${mutation.path} was deleted`;
  return `${mutation.path} was modified`;
}
