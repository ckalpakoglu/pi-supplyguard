/**
 * The single approved wrapper around the pinned `yaml` dependency (SPEC 22).
 *
 * RULE: nothing else in this repository may `import "yaml"`. All YAML access
 * goes through here so that parser options, hardening and failure behavior
 * live in exactly one reviewable place.
 *
 * Hardening choices:
 * - `merge: false`   -- no `<<` merge-key expansion.
 * - `maxAliasCount`  -- bounded alias expansion (billion-laughs resistance).
 * - `uniqueKeys`     -- duplicate keys are an error, not a silent override.
 * - no custom tags, no schema extensions, no JS-type resurrection.
 *
 * Parsing never throws: a malformed configuration file is a security-relevant
 * condition the caller must surface, not a crash inside a tool-call hook.
 */

import { parse } from "yaml";

export type YamlParseResult =
  | { readonly ok: true; readonly value: unknown }
  | { readonly ok: false; readonly error: string };

/** Maximum accepted document size. Configuration files are small. */
export const MAX_YAML_BYTES = 256 * 1024;

export function parseYaml(text: string): YamlParseResult {
  if (Buffer.byteLength(text, "utf8") > MAX_YAML_BYTES) {
    return { ok: false, error: `document exceeds ${MAX_YAML_BYTES} bytes` };
  }

  try {
    const value: unknown = parse(text, {
      merge: false,
      maxAliasCount: 10,
      uniqueKeys: true,
      prettyErrors: false,
      version: "1.2",
    });
    return { ok: true, value };
  } catch (error) {
    return { ok: false, error: describeError(error) };
  }
}

/** An empty or comment-only document parses to `null`; treat it as no data. */
export function isEmptyDocument(value: unknown): boolean {
  return value === null || value === undefined;
}

function describeError(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}
