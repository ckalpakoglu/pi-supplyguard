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

const MODULE_QUESTION =
  "Does this Go module source contain malicious, backdoor, or data-stealing " +
  "behavior that a careful human reviewer would call out?";

/**
 * Noul questions over `state`, all in ONE request; answers keyed by the same
 * ids. Additive evidence only. Any question left unanswered makes the whole
 * reply unusable: a partial verdict must not read as a clean one.
 */
async function ask(
  options: JevAnalyzerOptions,
  state: string,
  questions: Readonly<Record<string, string>>,
): Promise<{ readonly answers: Readonly<Record<string, number>> } | { readonly error: string }> {
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
    const document = await post(
      `${options.baseUrl ?? DEFAULT_BASE_URL}/v1/systemone`,
      {
        state,
        model: options.model ?? DEFAULT_MODEL,
        // Live-verified 2026-10-18 (D27): questions is a DICT keyed by id,
        // each { type: "noul", instructions }; the answer comes back as
        // answers.<id>.noul.
        questions: Object.fromEntries(
          Object.entries(questions).map(([id, instructions]) => [id, { type: "noul", instructions }]),
        ),
      },
      options.apiKey ?? "",
    );
    const answers =
      typeof document === "object" && document !== null && "answers" in document
        ? document.answers
        : undefined;
    if (typeof answers !== "object" || answers === null || Array.isArray(answers)) {
      return { error: "the analyzer returned no answers" };
    }

    const byId = new Map(Object.entries(answers));
    const result: Record<string, number> = {};
    for (const id of Object.keys(questions)) {
      const answer: unknown = byId.get(id);
      const noul =
        typeof answer === "object" && answer !== null && "type" in answer && answer.type === "noul" &&
        "noul" in answer
          ? answer.noul
          : undefined;
      if (typeof noul !== "number" || !Number.isFinite(noul)) {
        return { error: `the analyzer returned no usable answer for "${id}"` };
      }
      result[id] = noul;
    }
    return { answers: result };
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

      const result = await ask(options, state.slice(0, STATE_CHAR_BUDGET), { malicious: MODULE_QUESTION });
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

      const malicious = result.answers["malicious"] ?? 0;
      const findings =
        malicious >= ALERT_THRESHOLD
          ? [
              {
                origin: "external" as const,
                source: "jev" as const,
                code: "jev:malicious",
                // Experimental cap: the human decides; nothing auto-denies.
                decision: "ask" as const,
                message:
                  `Jev rates ${key} malicious with p=${malicious.toFixed(2)} ` +
                  `(confidence ${(2 * Math.abs(malicious - 0.5)).toFixed(2)}). ` +
                  `Read the flagged code before approving.`,
              },
            ]
          : [];
      cache.set(key, findings);
      return findings;
    },
  };
}

// ---------------------------------------------------------------------------
// M17: execution classifier (paranoid-only; PLAN-LOCAL-POLICY §3).
// Stage 1 reads the redacted COMMAND; stage 2 reads one local FILE the
// command executes and asks two questions in one request: is it harmful,
// and can its safety be judged from its own text at all.
// Never a supply-chain verdict -- that is Socket's job.
// ---------------------------------------------------------------------------

const COMMAND_QUESTION =
  "An AI coding agent is about to run this shell command. Is it harmful -- " +
  "destructive, exfiltrating data, opening a reverse shell, disabling security, " +
  "or running obfuscated code -- such that a careful engineer would stop it?";

const FILE_QUESTION =
  "An AI coding agent is about to execute this local script. Does it contain " +
  "harmful behavior -- destruction, exfiltration, persistence, a reverse shell, " +
  "or obfuscated payloads -- that a careful engineer would stop?";

/**
 * Stage 2 reads ONE file. A script whose behavior lives elsewhere -- local
 * imports, dynamic loading, encoded payloads -- looks clean to the harm
 * question; this question turns "cannot see it" into a human review instead
 * of a pass. Live-calibrated 2026-10-18: stdlib and well-known third-party
 * imports stay below the threshold (0.05–0.08).
 */
const OPACITY_QUESTION =
  "An AI coding agent is about to execute this local script. Can its safety NOT " +
  "be judged from this text alone -- because it imports modules from the local " +
  "project (not the standard library or well-known third-party packages), loads " +
  "or executes code dynamically (exec, eval, importlib, __import__, require of a " +
  "computed path, downloaded code), or is obfuscated or encoded -- so that a human " +
  "should review what it pulls in before it runs?";

/** What each question's high-confidence answer means for the human. */
const VERDICTS: Record<string, (label: string, p: number) => string> = {
  malicious: (label, p) =>
    `The execution classifier rates ${label} harmful (p=${p.toFixed(2)}). Read it before approving.`,
  opaque: (label, p) =>
    `The execution classifier cannot judge ${label} from its text alone (p=${p.toFixed(2)}): it ` +
    `imports local modules, loads code dynamically, or is obfuscated. Review the script — and ` +
    `what it pulls in — before approving.`,
};

/** Stage 2 reads at most this much of a file; the rest is the human's to read. */
export const FILE_CHAR_BUDGET = 120_000;
const COMMAND_CHAR_BUDGET = 8_000;

export interface ExecutionTarget {
  /** Already redacted by the caller (rail 3). */
  readonly command: string;
  /** A local file the command executes, already cleared by rail 1. */
  readonly file?: { readonly path: string; readonly text: string };
}

export function createExecutionClassifier(options: JevAnalyzerOptions) {
  // Retry loops cost one call: keyed by exact input.
  const cache = new Map<string, readonly ExternalFinding[]>();

  async function judge(
    label: string,
    state: string,
    questions: Readonly<Record<string, string>>,
  ): Promise<readonly ExternalFinding[]> {
    const key = `${Object.keys(questions).join(",")}:${state}`;
    const cached = cache.get(key);
    if (cached !== undefined) return cached;

    const result = await ask(options, state, questions);
    const findings: readonly ExternalFinding[] =
      "error" in result
        ? [
            {
              origin: "external",
              source: "classifier",
              code: "classifier-unavailable",
              // D6: fail soft. Commands are not trust decisions, and offline
              // vendored builds must survive paranoid.
              decision: "warn",
              message:
                `The execution classifier could not evaluate ${label} (${result.error}); it ` +
                `vouches for nothing. Local policy remains authoritative.`,
            },
          ]
        : Object.entries(result.answers).flatMap(([id, p]) =>
            // A low answer adds nothing -- the classifier can never acquit.
            p >= ALERT_THRESHOLD && VERDICTS[id] !== undefined
              ? [
                  {
                    origin: "external" as const,
                    source: "classifier",
                    code: id === "malicious" ? "classifier:harmful" : `classifier:${id}`,
                    // D5: ASK-capped while experimental; the human decides.
                    decision: "ask" as const,
                    message: VERDICTS[id](label, p),
                  },
                ]
              : [],
          );
    cache.set(key, findings);
    return findings;
  }

  return {
    async classify(target: ExecutionTarget): Promise<readonly ExternalFinding[]> {
      if (!options.enabled || options.apiKey === undefined || options.apiKey === "") return [];
      const findings = [
        ...(await judge("this command", target.command.slice(0, COMMAND_CHAR_BUDGET), {
          malicious: COMMAND_QUESTION,
        })),
      ];
      if (target.file !== undefined) {
        findings.push(
          ...(await judge(target.file.path, target.file.text.slice(0, FILE_CHAR_BUDGET), {
            malicious: FILE_QUESTION,
            opaque: OPACITY_QUESTION,
          })),
        );
      }
      return findings;
    },
  };
}
