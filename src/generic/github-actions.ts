/**
 * GitHub Actions reference policy (SPEC 15.1).
 *
 * `uses: actions/checkout@v4` is a MUTABLE reference: the tag can be moved to
 * any commit at any time by whoever controls the repository, and CI will run
 * whatever it points at next. A 40-character commit SHA cannot be moved.
 *
 * This lives in the generic layer, not in an ecosystem adapter: a Go project's
 * workflow is no more or less exposed than a Node one's, and SPEC 15.1 says so.
 */

import type { SupplyChainEvent } from "../core/events.ts";
import type { Profile } from "../core/profiles.ts";
import { isEmptyDocument, parseYaml } from "../core/yaml.ts";
import { GENERIC_ECOSYSTEM } from "./installers.ts";

/** Workflow files, relative to the repository root. */
export const WORKFLOW_GLOBS: readonly string[] = [
  ".github/workflows/*.yml",
  ".github/workflows/*.yaml",
];

export function isWorkflowPath(path: string): boolean {
  return /^\.github\/workflows\/[^/]+\.ya?ml$/.test(path);
}

/** A full commit SHA is the only immutable form GitHub accepts. */
const COMMIT_SHA = /^[0-9a-f]{40}$/;

export interface ActionReference {
  /** The whole `owner/repo@ref` value, or a local/docker form. */
  readonly uses: string;
  readonly action: string;
  readonly ref?: string;
  readonly immutable: boolean;
  /** True for `./local` and `docker://` forms, which pin differently. */
  readonly local: boolean;
}

/**
 * Collect every `uses:` value in a workflow document.
 *
 * Walks the parsed YAML rather than scanning lines: a `uses:` inside a comment
 * or a shell script block is not an action reference, and a regex cannot tell
 * the difference.
 */
export function collectActionReferences(text: string): readonly ActionReference[] {
  const parsed = parseYaml(text);
  if (!parsed.ok || isEmptyDocument(parsed.value)) return [];

  const found: ActionReference[] = [];
  walk(parsed.value, found, 0);
  return found;
}

const MAX_WALK_DEPTH = 32;

function walk(node: unknown, out: ActionReference[], depth: number): void {
  if (depth > MAX_WALK_DEPTH || node === null || typeof node !== "object") return;

  if (Array.isArray(node)) {
    for (const item of node) walk(item, out, depth + 1);
    return;
  }

  for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
    if (key === "uses" && typeof value === "string") {
      out.push(classifyReference(value));
      continue;
    }
    walk(value, out, depth + 1);
  }
}

export function classifyReference(uses: string): ActionReference {
  const value = uses.trim();

  // A local action or a container image is not a moving tag on someone else's
  // repository; digest policy for images is a separate question (M9).
  if (value.startsWith("./") || value.startsWith("../") || value.startsWith("docker://")) {
    return { uses: value, action: value, immutable: true, local: true };
  }

  const at = value.lastIndexOf("@");
  if (at <= 0) {
    // `uses: owner/repo` with no ref at all follows the default branch, which
    // is the most mutable reference there is.
    return { uses: value, action: value, immutable: false, local: false };
  }

  const action = value.slice(0, at);
  const ref = value.slice(at + 1);
  return { uses: value, action, ref, immutable: COMMIT_SHA.test(ref), local: false };
}

/**
 * Turn the mutable references in a workflow into events.
 *
 * SPEC 4.4: standard asks, hardened and paranoid deny. The adapter asserts the
 * stricter floor itself rather than the engine learning what a workflow is.
 */
export function inspectWorkflow(
  path: string,
  text: string,
  profile: Profile,
  options: { readonly changed: boolean },
): readonly SupplyChainEvent[] {
  const events: SupplyChainEvent[] = [];

  for (const reference of collectActionReferences(text)) {
    if (reference.local || reference.immutable) continue;

    events.push({
      eventClass: options.changed ? "CIReferenceChange" : "CIReferenceAdd",
      ecosystem: GENERIC_ECOSYSTEM,
      classification: "THIRD_PARTY_MUTATION",
      artifact: reference.action,
      summary:
        `${path} uses ${reference.uses}, a mutable reference: the ` +
        `${reference.ref === undefined ? "default branch" : `tag or branch "${reference.ref}"`} ` +
        `can be repointed at any commit. Pin a full 40-character commit SHA.`,
      ...(reference.ref === undefined ? {} : { version: reference.ref }),
      ...(profile === "standard" ? {} : { minimumDecision: "deny" as const }),
    });
  }

  return events;
}
