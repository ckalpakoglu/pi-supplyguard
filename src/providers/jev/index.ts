/**
 * Optional Jev analyzer (M10, PLAN-ZERO-DAY P1; KNOWN-GAPS §1.15).
 *
 * Human decision, 2026-09-27: Jev is NEVER a dependency. The local scanner
 * (`src/analyzers/content.ts`) is the baseline evidence and needs nothing;
 * this provider only ADDS findings when the operator deliberately enables it.
 * Deleting this directory must leave every gate and every test green — which
 * is why `src/index.ts` loads it dynamically, only when configured on.
 *
 * API shape verified against the published TypeSafe evaluation API as used by
 * the `is-malicious` scanner: `POST {base}/v1/systemone` with `{state, model,
 * questions}` and typed `answers`; key from the operator's environment, never
 * from a config file, never into audit, logs or prompts.
 */
import { collectModuleText } from "../../analyzers/content.ts";
import type { ExternalFinding } from "../../core/decisions.ts";

const DEFAULT_BASE_URL = "https://api.typesafe.ai";
const DEFAULT_MODEL = "jev-latest";
/** While experimental, a malicious verdict contributes at most an ASK. */
const ALERT_THRESHOLD = 0.7;
const STATE_CHAR_BUDGET = 120_000;

export interface JevAnalyzerOptions {
  readonly enabled: boolean;
  readonly baseUrl?: string;
  readonly model?: string;
  readonly apiKey?: string;
  /** Injected by tests; nothing in the suite reaches the network. */
  readonly post?: (url: string, body: unknown, apiKey: string) => Promise<unknown>;
}

interface JevAnswer {
  readonly type?: string;
  readonly id?: string;
  readonly p?: number;
}

/**
 * One Noul question over the module's source: does this code contain
 * malicious behavior? The answer is additive evidence only.
 */
async function ask(
  options: JevAnalyzerOptions,
  state: string,
): Promise<{ readonly malicious: number } | { readonly error: string }> {
  const post =
    options.post ??
    (async (url: string, body: unknown, apiKey: string) => {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
        body: JSON.stringify(body),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return (await response.json()) as unknown;
    });

  try {
    const document = (await post(
      `${options.baseUrl ?? DEFAULT_BASE_URL}/v1/systemone`,
      {
        state,
        model: options.model ?? DEFAULT_MODEL,
        questions: [
          {
            type: "noul",
            id: "malicious",
            question:
              "Does this Go module source contain malicious, backdoor, or data-stealing " +
              "behavior that a careful human reviewer would call out?",
          },
        ],
      },
      options.apiKey ?? "",
    )) as Record<string, unknown>;

    const answers = document["answers"];
    if (!Array.isArray(answers) || answers.length === 0) {
      return { error: "the analyzer returned no answers" };
    }
    const answer = answers[0] as JevAnswer;
    if (answer.type !== "noul" || typeof answer.p !== "number" || !Number.isFinite(answer.p)) {
      return { error: "the analyzer returned an unusable answer" };
    }
    return { malicious: answer.p };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

/**
 * Build the evidence provider. It is handed the same event list the Socket
 * provider sees; it only ever returns `ExternalFinding`s, so it can only
 * tighten (SPEC 13.5). Modules covered by `GOPRIVATE`/`GONOPROXY` are never
 * sent anywhere; neither is a module whose source cannot be read locally.
 */
export function createJevAnalyzer(options: JevAnalyzerOptions) {
  const cache = new Map<string, readonly ExternalFinding[]>();
  return {
    async evidenceFor(
      target: { readonly artifact: string; readonly version: string; readonly source: string },
    ): Promise<readonly ExternalFinding[]> {
      const key = `${target.artifact}@${target.version}`;
      if (!options.enabled || options.apiKey === undefined || options.apiKey === "") return [];
      const cached = cache.get(key);
      if (cached !== undefined) return cached;

      let state: string;
      try {
        state = await collectModuleText(target.source, STATE_CHAR_BUDGET);
      } catch {
        return []; // The local scanner already reported what it could.
      }
      if (state.trim() === "") return [];

      const result = await ask(options, state.slice(0, STATE_CHAR_BUDGET));
      if ("error" in result) {
        const findings: readonly ExternalFinding[] = [
          {
            origin: "external",
            source: "jev",
            code: "jev-unavailable",
            decision: "warn",
            message:
              `Jev could not evaluate ${key} (${result.error}); it vouches for nothing. ` +
              `Local policy and the local content scan remain authoritative.`,
          },
        ];
        cache.set(key, findings);
        return findings;
      }

      const findings =
        result.malicious >= ALERT_THRESHOLD
          ? [
              {
                origin: "external" as const,
                source: "jev" as const,
                code: "jev:malicious",
                // Experimental cap: the human decides; nothing auto-denies.
                decision: "ask" as const,
                message:
                  `Jev rates ${key} malicious with p=${result.malicious.toFixed(2)} ` +
                  `(confidence ${(2 * Math.abs(result.malicious - 0.5)).toFixed(2)}). ` +
                  `Read the flagged code before approving.`,
              },
            ]
          : [];
      cache.set(key, findings);
      return findings;
    },
  };
}
