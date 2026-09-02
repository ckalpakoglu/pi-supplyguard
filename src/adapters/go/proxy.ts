/**
 * Go module proxy lookup (SPEC 11.1, 16).
 *
 * This is the only place SupplyGuard reaches the network, and it asks exactly
 * one question: when was this module version published? It is used to enforce
 * the release cooldown -- a version nobody has looked at yet is the shape a
 * compromised release arrives in.
 *
 * PRIVACY IS THE FIRST CONSTRAINT. Querying a public proxy tells that proxy
 * which modules a repository depends on. `GOPRIVATE` and `GONOPROXY` exist
 * precisely to say "never send this module path anywhere", and they are honored
 * here BEFORE any request is built: a private module is reported as
 * `not-applicable`, never looked up, and never leaked. `GOPROXY=off` and
 * `direct` disable the lookup entirely, because the operator has said not to
 * talk to a proxy.
 */

import type { ReleaseLookup } from "../../core/release-age.ts";

export const DEFAULT_GOPROXY = "https://proxy.golang.org";

/** How long to wait for the proxy before giving up on the answer. */
export const PROXY_TIMEOUT_MS = 4_000;

/** Largest accepted `.info` document; it is three short fields. */
const MAX_INFO_BYTES = 64 * 1024;

export interface ProxyEnvironment {
  readonly GOPROXY?: string | undefined;
  readonly GOPRIVATE?: string | undefined;
  readonly GONOPROXY?: string | undefined;
}

/**
 * Escape a module path for a proxy URL.
 *
 * The Go module proxy protocol lower-cases the path and prefixes every
 * originally-uppercase letter with `!`, so `github.com/BurntSushi/toml` becomes
 * `github.com/!burnt!sushi/toml`. Without this, every module with a capital
 * letter in its path 404s and looks like an unavailable provider.
 */
export function escapeModulePath(modulePath: string): string {
  let out = "";
  for (const char of modulePath) {
    out += char >= "A" && char <= "Z" ? `!${char.toLowerCase()}` : char;
  }
  return out;
}

/**
 * Match one `GOPRIVATE`-style glob against a module path.
 *
 * Go matches these per path ELEMENT: `*` never crosses a `/`, and a pattern
 * matches a module whose leading elements it covers, so
 * `github.com/mycorp/*` matches `github.com/mycorp/lib/v2`.
 */
export function matchesPattern(pattern: string, modulePath: string): boolean {
  const patternParts = pattern.split("/").filter((part) => part !== "");
  const pathParts = modulePath.split("/").filter((part) => part !== "");
  if (patternParts.length === 0 || patternParts.length > pathParts.length) return false;

  return patternParts.every((part, index) => elementMatches(part, pathParts[index] ?? ""));
}

function elementMatches(pattern: string, element: string): boolean {
  // Build a regex for one element: `*` and `?` are the only metacharacters Go
  // honors here, and everything else is literal.
  let expression = "^";
  for (const char of pattern) {
    if (char === "*") expression += "[^/]*";
    else if (char === "?") expression += "[^/]";
    else expression += char.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`${expression}$`).test(element);
}

/** True when the operator has said this module must not reach a proxy. */
export function isPrivateModule(modulePath: string, env: ProxyEnvironment): boolean {
  const patterns = [env.GOPRIVATE, env.GONOPROXY]
    .filter((value): value is string => typeof value === "string" && value !== "")
    .flatMap((value) => value.split(","))
    .map((value) => value.trim())
    .filter((value) => value !== "");

  return patterns.some((pattern) => matchesPattern(pattern, modulePath));
}

/**
 * The proxy base URL to use, or `undefined` when the operator disabled proxies.
 *
 * `GOPROXY` is a comma/pipe-separated fallback list; the first HTTP(S) entry is
 * the one we ask. `off` and `direct` mean there is no proxy to ask.
 */
export function resolveProxyBase(env: ProxyEnvironment): string | undefined {
  const raw = env.GOPROXY;
  if (raw === undefined || raw.trim() === "") return DEFAULT_GOPROXY;

  for (const entry of raw.split(/[,|]/).map((value) => value.trim())) {
    if (entry === "" || entry === "direct") continue;
    if (entry === "off") return undefined;
    if (entry.startsWith("https://") || entry.startsWith("http://")) {
      return entry.replace(/\/+$/, "");
    }
  }
  return undefined;
}

/** Injectable for tests; the default is `globalThis.fetch`. */
export type FetchLike = (
  url: string,
  init: { readonly signal: AbortSignal },
) => Promise<{ readonly ok: boolean; readonly status: number; text(): Promise<string> }>;

export interface ProxyOptions {
  readonly env?: ProxyEnvironment;
  readonly fetch?: FetchLike;
  readonly timeoutMs?: number;
}

/**
 * Ask the proxy when `module@version` was published.
 *
 * Never throws: every failure -- disabled proxy, timeout, non-200, malformed
 * document -- becomes an `unavailable` result carrying a non-secret reason, and
 * the profile decides what that means (SPEC 16).
 */
export async function lookupReleaseDate(
  modulePath: string,
  version: string,
  options: ProxyOptions = {},
): Promise<ReleaseLookup> {
  const env = options.env ?? process.env;

  if (isPrivateModule(modulePath, env)) {
    return {
      kind: "not-applicable",
      reason: "the module is covered by GOPRIVATE/GONOPROXY and is never sent to a proxy",
    };
  }

  const base = resolveProxyBase(env);
  if (base === undefined) {
    return { kind: "not-applicable", reason: "GOPROXY disables proxy lookups" };
  }

  const doFetch = options.fetch ?? (globalThis.fetch as unknown as FetchLike | undefined);
  if (doFetch === undefined) {
    return { kind: "unavailable", reason: "this runtime has no fetch implementation" };
  }

  const url = `${base}/${escapeModulePath(modulePath)}/@v/${encodeURIComponent(version)}.info`;
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, options.timeoutMs ?? PROXY_TIMEOUT_MS);

  try {
    const response = await doFetch(url, { signal: controller.signal });
    if (!response.ok) {
      return { kind: "unavailable", reason: `the proxy answered HTTP ${response.status}` };
    }

    const body = await response.text();
    if (body.length > MAX_INFO_BYTES) {
      return { kind: "unavailable", reason: "the proxy returned an implausibly large document" };
    }

    const parsed: unknown = JSON.parse(body);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return { kind: "unavailable", reason: "the proxy returned an unexpected document" };
    }

    const time = (parsed as Record<string, unknown>)["Time"];
    if (typeof time !== "string") {
      return { kind: "unavailable", reason: "the proxy document carries no publication time" };
    }

    const publishedAt = new Date(time);
    if (Number.isNaN(publishedAt.getTime())) {
      return { kind: "unavailable", reason: "the proxy reported an unreadable publication time" };
    }

    return { kind: "known", publishedAt };
  } catch (error) {
    // Includes the abort. The message is the library's, never a credential.
    const detail =
      error instanceof Error && error.name === "AbortError"
        ? "the proxy did not answer in time"
        : "the proxy could not be reached";
    return { kind: "unavailable", reason: detail };
  } finally {
    clearTimeout(timer);
  }
}
