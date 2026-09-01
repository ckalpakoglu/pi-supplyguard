/**
 * Local remembered state (SPEC 8.2, 18.2).
 *
 * Workstation-local decisions live here instead of being written back into the
 * repository: SupplyGuard does not silently rewrite a project's configuration.
 *
 * State is advisory. A missing or corrupt state file is never an error and
 * never grants trust -- it degrades to "nothing remembered".
 */

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { isProfile, type Profile } from "./profiles.ts";

/**
 * Per-project remembered state.
 *
 * M1 records only what M1 can honestly know. Fields for later milestones
 * (Socket Firewall choice, vendor mode -- SPEC 18.2) are added by the
 * milestones that implement them.
 */
export interface ProjectState {
  readonly lastEffectiveProfile?: Profile;
  readonly lastSeenAt?: string;
}

export interface SupplyGuardState {
  readonly version: 1;
  readonly projects: Readonly<Record<string, ProjectState>>;
}

export const EMPTY_STATE: SupplyGuardState = Object.freeze({
  version: 1,
  projects: Object.freeze({}),
});

/** Maximum accepted state file size; this file is small metadata. */
const MAX_STATE_BYTES = 1024 * 1024;

function parseProjectState(raw: unknown): ProjectState | undefined {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return undefined;
  const record = raw as Record<string, unknown>;
  const state: { lastEffectiveProfile?: Profile; lastSeenAt?: string } = {};

  const profile = record["lastEffectiveProfile"];
  if (isProfile(profile)) state.lastEffectiveProfile = profile;

  const seenAt = record["lastSeenAt"];
  if (typeof seenAt === "string") state.lastSeenAt = seenAt;

  return state;
}

/** Interpret an untrusted parsed state document; unknown shapes are dropped. */
export function parseState(raw: unknown): SupplyGuardState {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return EMPTY_STATE;
  const doc = raw as Record<string, unknown>;
  const projectsRaw = doc["projects"];
  if (typeof projectsRaw !== "object" || projectsRaw === null || Array.isArray(projectsRaw)) {
    return EMPTY_STATE;
  }

  const projects: Record<string, ProjectState> = {};
  for (const [key, value] of Object.entries(projectsRaw as Record<string, unknown>)) {
    const parsed = parseProjectState(value);
    if (parsed !== undefined) projects[key] = parsed;
  }

  return { version: 1, projects };
}

export async function loadState(path: string): Promise<SupplyGuardState> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch {
    return EMPTY_STATE;
  }

  if (Buffer.byteLength(text, "utf8") > MAX_STATE_BYTES) return EMPTY_STATE;

  try {
    return parseState(JSON.parse(text));
  } catch {
    return EMPTY_STATE;
  }
}

/**
 * Write state atomically (temp file + rename) with 0600 permissions, so a
 * crash mid-write cannot leave a truncated file that reads as "nothing
 * remembered" in a way an observer could mistake for a clean baseline.
 */
export async function saveState(path: string, state: SupplyGuardState): Promise<void> {
  const dir = dirname(path);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const tmp = join(dir, `.state.${process.pid}.${Date.now()}.tmp`);
  await writeFile(tmp, `${JSON.stringify(state, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  await rename(tmp, path);
}

export function getProjectState(
  state: SupplyGuardState,
  repoRoot: string,
): ProjectState | undefined {
  return state.projects[repoRoot];
}

/** Pure update: returns a new state with `repoRoot` patched. */
export function setProjectState(
  state: SupplyGuardState,
  repoRoot: string,
  patch: ProjectState,
): SupplyGuardState {
  const existing = state.projects[repoRoot] ?? {};
  return {
    version: 1,
    projects: { ...state.projects, [repoRoot]: { ...existing, ...patch } },
  };
}
