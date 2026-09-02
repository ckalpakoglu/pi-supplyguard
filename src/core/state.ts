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
 * One answered ask-once project question (SPEC 9.2, 13.3, 18.2).
 *
 * Only answers a HUMAN gave are stored. A value SupplyGuard picked because no
 * human was reachable is deliberately not persisted: writing it down would
 * turn "nobody was asked" into "somebody decided".
 */
export interface ProjectDecisionState {
  readonly value: string;
  readonly decidedAt: string;
}

/**
 * Per-project remembered state.
 *
 * SPEC 18.2 sketches this as nested per-subsystem objects (`go.vendorMode`,
 * `socket.firewallDecision`). It is stored here as one flat map keyed by the
 * adapter/provider-namespaced decision id, so the core needs no schema for
 * every ecosystem it will ever carry -- `decisions["go.vendorMode"]` holds
 * exactly what the SPEC example calls `go.vendorMode`.
 */
export interface ProjectState {
  readonly lastEffectiveProfile?: Profile;
  readonly lastSeenAt?: string;
  readonly decisions?: Readonly<Record<string, ProjectDecisionState>>;
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
  const state: {
    lastEffectiveProfile?: Profile;
    lastSeenAt?: string;
    decisions?: Record<string, ProjectDecisionState>;
  } = {};

  const profile = record["lastEffectiveProfile"];
  if (isProfile(profile)) state.lastEffectiveProfile = profile;

  const seenAt = record["lastSeenAt"];
  if (typeof seenAt === "string") state.lastSeenAt = seenAt;

  const decisions = parseDecisions(record["decisions"]);
  if (decisions !== undefined) state.decisions = decisions;

  return state;
}

function parseDecisions(
  raw: unknown,
): Record<string, ProjectDecisionState> | undefined {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return undefined;

  const decisions: Record<string, ProjectDecisionState> = {};
  for (const [id, value] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) continue;
    const entry = value as Record<string, unknown>;
    const answer = entry["value"];
    const decidedAt = entry["decidedAt"];
    // A stored answer without both fields is not trusted: an answer with no
    // recorded time is not evidence that a human ever gave it.
    if (typeof answer !== "string" || typeof decidedAt !== "string") continue;
    decisions[id] = { value: answer, decidedAt };
  }
  return Object.keys(decisions).length === 0 ? undefined : decisions;
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

/** Pure update: record one answered project question (SPEC 9.2, 18.2). */
export function setProjectDecision(
  state: SupplyGuardState,
  repoRoot: string,
  id: string,
  decision: ProjectDecisionState,
): SupplyGuardState {
  const existing = state.projects[repoRoot] ?? {};
  return setProjectState(state, repoRoot, {
    decisions: { ...existing.decisions, [id]: decision },
  });
}

export function getProjectDecisions(
  state: SupplyGuardState,
  repoRoot: string,
): Readonly<Record<string, ProjectDecisionState>> {
  return state.projects[repoRoot]?.decisions ?? {};
}
