/**
 * Dependency justification (SPEC 11.2, 17.1).
 *
 * SPEC 11.2 says a dependency approval REQUIRES a purpose, whether the standard
 * library was considered, and why it is insufficient. Those are the agent's
 * answers, and a `tool_call` handler cannot ask for them: it sees a command,
 * not a rationale. So SupplyGuard registers a tool the agent must call first,
 * and refuses dependency operations that arrive without one.
 *
 * WHAT THIS IS NOT: a justification is not an approval. The agent supplies
 * evidence about its own intent; a human still decides (SPEC 17.1). Recording a
 * justification can only ever ADD a required step -- an unjustified operation is
 * denied, and a justified one still asks.
 *
 * Justifications are one-shot and in-memory. They are scoped to one artifact at
 * one exact version for one execution (SPEC 17.2), so they are consumed when
 * used and are never persisted: durable trust in a version is exactly what
 * SPEC 11.3 rules out ("v1 does not include 'Always approve this dependency'").
 */

import type { SupplyChainEvent, SupplyChainEventClass } from "./events.ts";

/** The tool the agent calls before adding or changing a dependency. */
export const JUSTIFY_TOOL = "supplyguard_justify_dependency";

/**
 * Event classes that represent a NEW third-party trust decision.
 *
 * Removal is excluded: it reduces third-party surface, and demanding a
 * rationale for taking a dependency out would be friction pointing the wrong
 * way. Lockfile and fetch events are excluded because they name no artifact to
 * justify.
 */
const JUSTIFIABLE_EVENT_CLASSES: ReadonlySet<SupplyChainEventClass> = new Set([
  "DependencyAdd",
  "DependencyUpgrade",
  "DependencyDowngrade",
  "DependencyReplace",
  "ToolInstall",
  "ToolUpgrade",
  "ThirdPartyExecution",
]);

/**
 * Does this event need a justification before a human can be asked about it?
 *
 * Only when the artifact and version are both known: an operation SupplyGuard
 * cannot name is denied by the exact-version rules long before it gets here,
 * and asking the agent to justify something neither side can identify would be
 * theatre.
 */
export function needsJustification(event: SupplyChainEvent): boolean {
  return (
    JUSTIFIABLE_EVENT_CLASSES.has(event.eventClass) &&
    event.artifact !== undefined &&
    event.version !== undefined
  );
}

export interface Justification {
  readonly artifact: string;
  readonly version: string;
  /** What the dependency is for. Non-secret free text from the agent. */
  readonly purpose: string;
  readonly stdlibConsidered: boolean;
  /** Why the standard library does not cover it. */
  readonly stdlibInsufficientReason: string;
  /** ISO-8601 timestamp of the tool call that recorded it. */
  readonly recordedAt: string;
}

/** Scope key: one artifact at one exact version (SPEC 11.3, 17.2). */
export function justificationKey(artifact: string, version: string): string {
  return `${artifact}@${version}`;
}

/**
 * Largest number of pending justifications kept per repository.
 *
 * An agent that calls the tool without ever running the operation would
 * otherwise grow this without bound. The oldest is dropped, which can only
 * cause a re-justification, never an unjustified approval.
 */
const MAX_PENDING = 64;

export interface JustificationStore {
  /** Record a justification. Replaces any pending one for the same scope. */
  record(justification: Justification): void;
  /** Look one up without consuming it. */
  peek(artifact: string, version: string): Justification | undefined;
  /**
   * Take the justification for this scope, removing it.
   *
   * One-shot by construction: a second operation on the same artifact and
   * version is a second trust decision and needs its own rationale.
   */
  take(artifact: string, version: string): Justification | undefined;
  size(): number;
}

export function createJustificationStore(): JustificationStore {
  const pending = new Map<string, Justification>();

  return {
    record(justification) {
      const key = justificationKey(justification.artifact, justification.version);
      pending.delete(key);
      pending.set(key, justification);
      while (pending.size > MAX_PENDING) {
        const oldest = pending.keys().next();
        if (oldest.done === true) break;
        pending.delete(oldest.value);
      }
    },

    peek(artifact, version) {
      return pending.get(justificationKey(artifact, version));
    },

    take(artifact, version) {
      const key = justificationKey(artifact, version);
      const found = pending.get(key);
      pending.delete(key);
      return found;
    },

    size: () => pending.size,
  };
}

export interface JustificationParseError {
  readonly ok: false;
  /** Non-secret message returned to the agent, naming what is missing. */
  readonly message: string;
}

export type JustificationParseResult =
  | { readonly ok: true; readonly justification: Justification }
  | JustificationParseError;

/** Longest accepted free-text field; prompts and audit records stay readable. */
const MAX_TEXT = 500;

function readText(
  raw: Record<string, unknown>,
  field: string,
  problems: string[],
): string {
  const value = raw[field];
  if (typeof value !== "string" || value.trim() === "") {
    problems.push(`"${field}" must be a non-empty string`);
    return "";
  }
  if (value.length > MAX_TEXT) {
    problems.push(`"${field}" must be at most ${MAX_TEXT} characters`);
    return "";
  }
  return value.trim();
}

/**
 * Interpret untrusted tool arguments.
 *
 * SECURITY: this is a trust boundary. The parameter schema handed to the model
 * is a hint, not a guarantee, so every field is checked here. A malformed call
 * is an error the agent can read and correct -- never a partially accepted
 * justification.
 */
export function parseJustification(
  raw: unknown,
  recordedAt: string,
): JustificationParseResult {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, message: `${JUSTIFY_TOOL}: arguments must be an object.` };
  }

  const record = raw as Record<string, unknown>;
  const problems: string[] = [];

  const artifact = readText(record, "module", problems);
  const version = readText(record, "version", problems);
  const purpose = readText(record, "purpose", problems);
  const stdlibInsufficientReason = readText(record, "stdlibInsufficientReason", problems);

  const stdlibConsidered = record["stdlibConsidered"];
  if (typeof stdlibConsidered !== "boolean") {
    problems.push(`"stdlibConsidered" must be a boolean`);
  }

  if (problems.length > 0) {
    return {
      ok: false,
      message: `${JUSTIFY_TOOL}: ${problems.join("; ")}.`,
    };
  }

  return {
    ok: true,
    justification: {
      artifact,
      version,
      purpose,
      stdlibConsidered: stdlibConsidered === true,
      stdlibInsufficientReason,
      recordedAt,
    },
  };
}

/** SPEC 11.2 -- the parameters the approval object is built from. */
export const JUSTIFY_TOOL_PARAMETERS = {
  type: "object",
  properties: {
    module: {
      type: "string",
      description:
        "Exact module or package path being added, upgraded or executed, e.g. github.com/foo/bar.",
    },
    version: {
      type: "string",
      description:
        "Exact version, e.g. v1.7.2. Must match the version the operation uses; a different version is a separate trust decision.",
    },
    purpose: {
      type: "string",
      description: "What this dependency is for in this codebase, in one or two sentences.",
    },
    stdlibConsidered: {
      type: "boolean",
      description: "Whether the standard library was considered as an alternative.",
    },
    stdlibInsufficientReason: {
      type: "string",
      description:
        "Why the standard library does not cover this need, or why it was not considered.",
    },
  },
  required: ["module", "version", "purpose", "stdlibConsidered", "stdlibInsufficientReason"],
  additionalProperties: false,
} as const;

/** Approval-prompt lines for one justified artifact (SPEC 11.3). */
export function describeJustification(justification: Justification): string[] {
  return [
    `Purpose                  ${justification.purpose}`,
    `Stdlib considered        ${justification.stdlibConsidered ? "yes" : "no"}`,
    `Why not stdlib           ${justification.stdlibInsufficientReason}`,
  ];
}
