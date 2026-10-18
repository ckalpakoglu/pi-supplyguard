/**
 * Local policy rules (M15, SPEC §8.5): operator-authored match -> decision
 * rules, enforced offline in every profile.
 *
 * Tighten-only: `warn | ask | deny`, never `allow`. Global and project rules
 * are simply concatenated -- a project rule can add to a global rule, never
 * replace it, even under the same id. A malformed rule is skipped with a
 * warning; skipping loses protection but cannot open a hole.
 */
import type { Decision } from "../core/decisions.ts";

export type RuleSource = "global" | "project";

export interface PolicyRuleMatch {
  /** Wrapper-stripped argv[0] of any command in the call. */
  readonly command?: string;
  /** Any argument containing any listed string. */
  readonly argsContain?: readonly string[];
  readonly toolName?: string;
  /** A write (shell writer or file tool) under this directory. */
  readonly writePrefix?: string;
  /** Any path operand or file-tool path under this directory. */
  readonly readPrefix?: string;
  /** `path.matchesGlob` against any path operand or file-tool path. */
  readonly pathGlob?: string;
}

export interface PolicyRule {
  readonly id: string;
  readonly source: RuleSource;
  readonly decision: Exclude<Decision, "allow">;
  readonly match: PolicyRuleMatch;
  /** Shown to the human in the prompt. */
  readonly reason?: string;
}

const DECISIONS = ["warn", "ask", "deny"];
const STRING_KEYS = ["command", "toolName", "writePrefix", "readPrefix", "pathGlob"];

/** Interpret an untrusted `policies:` list; valid entries load, each invalid one warns. */
export function parsePolicyRules(
  raw: unknown,
  source: RuleSource,
): { readonly rules: readonly PolicyRule[]; readonly warnings: readonly string[] } {
  if (raw === undefined || raw === null) return { rules: [], warnings: [] };
  if (!Array.isArray(raw)) return { rules: [], warnings: [`"policies" is not a list; ignored.`] };

  const rules: PolicyRule[] = [];
  const warnings: string[] = [];
  raw.forEach((entry: unknown, index) => {
    const record = typeof entry === "object" && entry !== null && !Array.isArray(entry)
      ? (entry as Record<string, unknown>)
      : {};
    const { id, decision, match, reason } = record;
    const where = `policies[${index}]${typeof id === "string" ? ` ("${id}")` : ""}`;

    if (typeof id !== "string" || id.trim() === "") {
      warnings.push(`${where}: needs a non-empty "id"; ignored.`);
      return;
    }
    if (typeof decision !== "string" || !DECISIONS.includes(decision)) {
      warnings.push(`${where}: "decision" must be warn, ask or deny -- never allow, a rule may only tighten; ignored.`);
      return;
    }

    const valid: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(
      typeof match === "object" && match !== null && !Array.isArray(match) ? match : {},
    )) {
      const ok = key === "argsContain"
        ? Array.isArray(value) && value.length > 0 && value.every((v) => typeof v === "string" && v !== "")
        : STRING_KEYS.includes(key) && typeof value === "string" && value.trim() !== "";
      if (ok) valid[key] = value;
      else warnings.push(`${where}: match.${key} is unknown or malformed; ignored.`);
    }
    if (Object.keys(valid).length === 0) {
      warnings.push(`${where}: "match" has no usable key; ignored.`);
      return;
    }

    rules.push({
      id,
      source,
      decision: decision as PolicyRule["decision"],
      match: valid as PolicyRuleMatch,
      ...(typeof reason === "string" && reason !== "" ? { reason } : {}),
    });
  });
  return { rules, warnings };
}
