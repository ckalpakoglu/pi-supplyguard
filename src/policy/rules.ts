/**
 * Local policy rules (M15, PLAN-LOCAL-POLICY §3): operator-authored
 * match -> decision rules, enforced offline in every profile.
 *
 * The contract is the tighten-only lattice (SPEC 8.2, decisions D1-D10):
 * `warn | ask | deny` only — an `allow` rule is an exception primitive and is
 * rejected at load; rules compose with everything else by most-restrictive.
 * Malformed rules are ignored loudly (warn + status + audit), because rules
 * only tighten: ignoring one loses protection, never opens a hole.
 */


/** Decisions a rule may carry, weakest to strongest. */
const RULE_DECISIONS = ["warn", "ask", "deny"] as const;

export type RuleDecision = (typeof RULE_DECISIONS)[number];

/** Where a rule was declared; the compiled floor carries no rules. */
export type RuleSource = "global" | "project";

export const RULE_DECISION_RANK: Record<RuleDecision, number> = {
  warn: 0,
  ask: 1,
  deny: 2,
};

/** Total rules across all layers; beyond this the rest are dropped loudly. */
export const RULE_CAP = 200;



export interface PolicyRuleMatchSpec {
  /** Parsed, wrapper-stripped argv[0] of any command in the call. */
  readonly command?: string;
  /** Any argument containing any listed string. */
  readonly argsContain?: readonly string[];
  /** Host tool name, e.g. `edit`. */
  readonly toolName?: string;
  /** A write (shell writer or file tool) under this directory prefix. */
  readonly writePrefix?: string;
  /** Any path operand or file-tool input under this directory prefix. */
  readonly readPrefix?: string;
  /** Glob against any path operand or file-tool input. */
  readonly pathGlob?: string;
}

export interface PolicyRule {
  readonly id: string;
  readonly source: RuleSource;
  readonly decision: RuleDecision;
  readonly match: PolicyRuleMatchSpec;
  /** Shown to the human in the prompt; never a secret. */
  readonly reason?: string;
}

export interface ParsedRules {
  readonly rules: readonly PolicyRule[];
  readonly warnings: readonly string[];
}

const MATCH_KEYS = ["command", "argsContain", "toolName", "writePrefix", "readPrefix", "pathGlob"] as const;

type MatchKey = (typeof MATCH_KEYS)[number];

const STRING_MATCH_KEYS: readonly MatchKey[] = ["command", "toolName", "writePrefix", "readPrefix", "pathGlob"];

function readStringList(value: unknown): readonly string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const items = value.filter((item): item is string => typeof item === "string" && item !== "");
  return items.length === 0 ? undefined : items;
}

/**
 * Interpret an untrusted `policies:` list. Each invalid entry is skipped with
 * a warning naming the index and the reason; valid siblings still load.
 */
export function parsePolicyRules(raw: unknown, source: RuleSource): ParsedRules {
  const warnings: string[] = [];
  if (raw === undefined || raw === null) return { rules: [], warnings };
  if (!Array.isArray(raw)) {
    return { rules: [], warnings: [`"policies" is not a list; ignored.`] };
  }

  const rules: PolicyRule[] = [];
  raw.forEach((entry, index) => {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      warnings.push(`policies[${index}]: not a mapping; ignored.`);
      return;
    }
    const record = entry as Record<string, unknown>;

    const id = record["id"];
    if (typeof id !== "string" || id.trim() === "") {
      warnings.push(`policies[${index}]: missing or empty "id"; ignored.`);
      return;
    }

    const decision = record["decision"];
    if (decision === "allow") {
      warnings.push(
        `policies[${index}] ("${id}"): decision "allow" is not supported -- an allow ` +
          `rule could weaken a stricter layer; ignored. Suppressing a warning is a ` +
          `scoped, one-shot prompt decision, not a standing rule.`,
      );
      return;
    }
    if (typeof decision !== "string" || !RULE_DECISIONS.includes(decision as RuleDecision)) {
      warnings.push(`policies[${index}] ("${id}"): "decision" must be one of warn|ask|deny; ignored.`);
      return;
    }

    const rawMatch = record["match"];
    if (typeof rawMatch !== "object" || rawMatch === null || Array.isArray(rawMatch)) {
      warnings.push(`policies[${index}] ("${id}"): missing "match"; ignored.`);
      return;
    }
    const matchRecord = rawMatch as Record<string, unknown>;

    const match: { -readonly [K in MatchKey]?: PolicyRuleMatchSpec[K] } = {};
    let matched = 0;
    for (const key of Object.keys(matchRecord)) {
      if (!MATCH_KEYS.includes(key as MatchKey)) {
        warnings.push(`policies[${index}] ("${id}"): unknown match key "${key}"; ignored.`);
        continue;
      }
      const value = matchRecord[key];
      if (STRING_MATCH_KEYS.includes(key as MatchKey)) {
        if (typeof value !== "string" || value.trim() === "") {
          warnings.push(`policies[${index}] ("${id}"): match.${key} must be a non-empty string; ignored.`);
          continue;
        }
        match[key as "command"] = value;
        matched += 1;
      } else if (key === "argsContain") {
        const list = readStringList(value);
        if (list === undefined) {
          warnings.push(`policies[${index}] ("${id}"): match.argsContain must be a non-empty string list; ignored.`);
          continue;
        }
        match.argsContain = list;
        matched += 1;
      }
    }
    if (matched === 0) {
      warnings.push(`policies[${index}] ("${id}"): "match" has no recognized key; ignored.`);
      return;
    }

    const reason = record["reason"];
    if (reason !== undefined && typeof reason !== "string") {
      warnings.push(`policies[${index}] ("${id}"): "reason" is not a string; dropped.`);
    }

    rules.push({
      id,
      source,
      decision: decision as RuleDecision,
      match: match as PolicyRuleMatchSpec,
      ...(typeof reason === "string" && reason !== "" ? { reason } : {}),
    });
  });

  return { rules, warnings };
}

export interface MergedRules {
  readonly rules: readonly PolicyRule[];
  readonly warnings: readonly string[];
}

/**
 * Union two rule layers. Same id in both: the STRICTER decision wins (a layer
 * may tighten, never weaken) with a warning. The cap drops the tail loudly;
 * kept rules are the earliest layers' first, matching load order.
 */
export function mergePolicyRules(
  base: readonly PolicyRule[],
  layer: readonly PolicyRule[],
  layerName: string,
): MergedRules {
  const warnings: string[] = [];
  const byId = new Map<string, PolicyRule>();
  for (const rule of base) byId.set(rule.id, rule);

  for (const rule of layer) {
    const existing = byId.get(rule.id);
    if (existing === undefined) {
      byId.set(rule.id, rule);
      continue;
    }
    if (RULE_DECISION_RANK[rule.decision] > RULE_DECISION_RANK[existing.decision]) {
      byId.set(rule.id, rule);
      warnings.push(
        `${layerName}: rule "${rule.id}" appears in two layers; the stricter decision ` +
          `"${rule.decision}" wins over "${existing.decision}".`,
      );
    } else if (RULE_DECISION_RANK[rule.decision] < RULE_DECISION_RANK[existing.decision]) {
      warnings.push(
        `${layerName}: rule "${rule.id}" appears in two layers; the established stricter ` +
          `decision "${existing.decision}" stands over "${rule.decision}".`,
      );
    }
  }

  const rules = [...byId.values()];
  if (rules.length > RULE_CAP) {
    const dropped = rules.slice(RULE_CAP).map((rule) => rule.id);
    warnings.push(
      `${layerName}: ${rules.length} policy rules exceed the cap of ${RULE_CAP}; ` +
        `dropped: ${dropped.join(", ")}.`,
    );
  }
  return { rules: rules.slice(0, RULE_CAP), warnings };
}
