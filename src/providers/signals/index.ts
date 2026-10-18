/**
 * Repository signals (M14, PLAN-ZERO-DAY P5): class C — the compromised
 * release moment.
 *
 * An archived repository, or one whose owner changed hands, releasing a fresh
 * version is the shape several real incidents shared. The GitHub repository
 * API answers all three questions in one request; no token is required (60
 * requests/hour anonymous, and results are cached per process), though
 * GITHUB_TOKEN is honored when present.
 *
 * Opt-in (`signals.enabled`, default off) and additive-only, exactly like the
 * other external providers: a signal can add a reason to refuse and never
 * removes one.
 */

import type { ExternalFinding } from "../../core/decisions.ts";

export interface RepoSignalsOptions {
  readonly token?: string;
  /** Injected by tests; nothing in the suite reaches the network. */
  readonly fetch?: (url: string, headers: Record<string, string>) => Promise<unknown>;
  readonly now?: () => Date;
}

export interface RepoSignals {
  readonly owner?: string;
  readonly archived?: boolean;
  readonly pushedAt?: Date;
  readonly stars?: number;
}

async function read(
  ownerRepo: string,
  options: RepoSignalsOptions,
): Promise<{ readonly signals?: RepoSignals; readonly error?: string }> {
  const headers: Record<string, string> = { accept: "application/vnd.github+json" };
  if (options.token !== undefined && options.token !== "") {
    headers.authorization = `Bearer ${options.token}`;
  }
  const doFetch =
    options.fetch ??
    (async (url: string, heads: Record<string, string>) => {
      const response = await fetch(url, { headers: heads, redirect: "manual" });
      if (response.status === 301 || response.status === 302) {
        return { status: response.status, location: response.headers.get("location") };
      }
      return (await response.json()) as unknown;
    });

  try {
    const answer = (await doFetch(
      `https://api.github.com/repos/${ownerRepo}`,
      headers,
    )) as Record<string, unknown>;

    if (typeof answer["status"] === "number" && (answer["status"] === 301 || answer["status"] === 302)) {
      return { error: "transferred" };
    }
    if (answer["message"] !== undefined) {
      return { error: String(answer["message"]).slice(0, 120) };
    }

    const owner = answer["owner"];
    const pushed = answer["pushed_at"];
    const stars = answer["stargazers_count"];
    return {
      signals: {
        ...(typeof owner === "object" && owner !== null && "login" in owner
          ? { owner: String((owner as Record<string, unknown>)["login"]) }
          : {}),
        ...(answer["archived"] === true ? { archived: true } : {}),
        ...(typeof pushed === "string" ? { pushedAt: new Date(pushed) } : {}),
        ...(typeof stars === "number" ? { stars } : {}),
      },
    };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

export function createRepoSignalsProvider(options: RepoSignalsOptions = {}) {
  const cache = new Map<string, { readonly signals?: RepoSignals; readonly error?: string }>();
  const now = options.now ?? (() => new Date());

  return {
    async evidenceFor(artifact: string, version: string): Promise<readonly ExternalFinding[]> {
      // host/owner/repo[/…] — the repository the module lives in.
      const parts = artifact.split("/");
      if (parts.length < 3) return [];
      const ownerRepo = `${parts[1]}/${parts[2]}`;

      const key = ownerRepo;
      if (!cache.has(key)) cache.set(key, await read(ownerRepo, options));
      const { signals, error } = cache.get(key) ?? {};

      if (error === "transferred") {
        return [
          {
            origin: "external",
            source: "signals",
            code: "signal:transferred",
            decision: "ask",
            message:
              `the repository behind ${artifact} answers at a different owner (HTTP 301/302). ` +
              `A transferred repository releasing ${version} is the compromised-release shape; ` +
              `confirm who runs it now before approving.`,
          },
        ];
      }
      if (signals?.archived === true) {
        return [
          {
            origin: "external",
            source: "signals",
            code: "signal:archived",
            decision: "ask",
            message:
              `the repository behind ${artifact} is ARCHIVED and does not release code anymore. ` +
              `${version} from an archived repository is either a takeover or a mirror; verify.`,
          },
        ];
      }
      if (error !== undefined) {
        // Opt-in and advisory: an unreachable signals API withholds nothing.
        return [];
      }
      if (
        signals?.pushedAt !== undefined &&
        now().getTime() - signals.pushedAt.getTime() < 7 * 24 * 3600 * 1000 &&
        (signals.stars ?? 0) < 5
      ) {
        return [
          {
            origin: "external",
            source: "signals",
            code: "signal:fresh-repo",
            decision: "ask",
            message:
              `the repository behind ${artifact} was created or pushed very recently and has ` +
              `almost no history (<5 stars). ${version} is its first-mover risk.`,
          },
        ];
      }
      return [];
    },
  };
}
