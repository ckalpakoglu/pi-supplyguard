/**
 * OSV vulnerability lookup for Go modules (SPEC 16).
 *
 * OSV (osv.dev) is the open, credential-free vulnerability database Go's own
 * tooling draws on, which makes it the obvious default provider: no account, no
 * token, no per-seat licence to make a security control conditional on.
 *
 * PRIVACY: querying tells osv.dev which modules a repository depends on, so the
 * same rule as the module proxy applies -- a module covered by
 * `GOPRIVATE`/`GONOPROXY` is never sent, and `GOPROXY=off` disables the lookup
 * along with everything else that leaves the machine. An internal module's name
 * is not something a security tool gets to disclose on the operator's behalf.
 */

import {
  parseSeverity,
  type Severity,
  type VulnerabilityFinding,
  type VulnerabilityLookup,
} from "../../core/vulnerability.ts";
import { isPrivateModule, resolveProxyBase, type FetchLike, type ProxyEnvironment } from "./proxy.ts";

export const DEFAULT_OSV_ENDPOINT = "https://api.osv.dev/v1/query";

export const OSV_TIMEOUT_MS = 5_000;

/** Largest accepted response; an advisory list for one module is small. */
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

/** Cap on advisories carried into a finding message and audit record. */
const MAX_FINDINGS = 50;

export interface OsvOptions {
  readonly env?: ProxyEnvironment;
  readonly fetch?: OsvFetch;
  readonly timeoutMs?: number;
  readonly endpoint?: string;
}

export type OsvFetch = (
  url: string,
  init: {
    readonly method: string;
    readonly headers: Readonly<Record<string, string>>;
    readonly body: string;
    readonly signal: AbortSignal;
  },
) => Promise<{ readonly ok: boolean; readonly status: number; text(): Promise<string> }>;

/**
 * Read a severity out of an OSV entry.
 *
 * OSV records severity in several places depending on which database fed it.
 * `database_specific.severity` is the plain word GitHub advisories carry; the
 * `severity` array carries CVSS vectors, from which only the base score band is
 * needed here. Anything unreadable stays `unknown`, which is a policy outcome
 * in its own right (SPEC 16) rather than a default of "mild".
 */
export function readSeverity(entry: Record<string, unknown>): Severity {
  const databaseSpecific = entry["database_specific"];
  if (typeof databaseSpecific === "object" && databaseSpecific !== null) {
    const named = parseSeverity((databaseSpecific as Record<string, unknown>)["severity"]);
    if (named !== "unknown") return named;
  }

  const severities = entry["severity"];
  if (Array.isArray(severities)) {
    for (const item of severities) {
      if (typeof item !== "object" || item === null) continue;
      const score = (item as Record<string, unknown>)["score"];
      if (typeof score !== "string") continue;
      const band = cvssBand(score);
      if (band !== "unknown") return band;
    }
  }

  return "unknown";
}

/**
 * Map a CVSS v3/v4 vector to a severity band.
 *
 * Only the qualitative band matters here, and computing a base score from the
 * vector is a specification of its own. The impact and exploitability metrics
 * that separate critical from high are read directly instead: a vector with no
 * numeric score attached yields `unknown`, honestly.
 */
export function cvssBand(vector: string): Severity {
  const numeric = /(?:^|\/)(?:CVSS:[\d.]+\/)?.*?\b(\d+\.\d)\b\s*$/.exec(vector.trim());
  const score = numeric?.[1] === undefined ? Number.NaN : Number(numeric[1]);
  if (!Number.isFinite(score)) return "unknown";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "moderate";
  if (score > 0) return "low";
  return "unknown";
}

function toFinding(entry: unknown): VulnerabilityFinding | undefined {
  if (typeof entry !== "object" || entry === null || Array.isArray(entry)) return undefined;
  const record = entry as Record<string, unknown>;

  // A withdrawn advisory is one the database retracted; acting on it would be
  // reporting a vulnerability that its own publisher says is not one.
  if (typeof record["withdrawn"] === "string") return undefined;

  const id = record["id"];
  if (typeof id !== "string" || id === "") return undefined;

  const summary = record["summary"];
  const details = record["details"];
  const text =
    typeof summary === "string" && summary !== ""
      ? summary
      : typeof details === "string" && details !== ""
        ? details
        : "no summary provided";

  return {
    id,
    severity: readSeverity(record),
    summary: text.slice(0, 300).replace(/\s+/g, " ").trim(),
    ...(fixedVersions(record).length === 0 ? {} : { fixedIn: fixedVersions(record) }),
  };
}

function fixedVersions(entry: Record<string, unknown>): readonly string[] {
  const affected = entry["affected"];
  if (!Array.isArray(affected)) return [];

  const fixed: string[] = [];
  for (const item of affected) {
    if (typeof item !== "object" || item === null) continue;
    const ranges = (item as Record<string, unknown>)["ranges"];
    if (!Array.isArray(ranges)) continue;
    for (const range of ranges) {
      if (typeof range !== "object" || range === null) continue;
      const events = (range as Record<string, unknown>)["events"];
      if (!Array.isArray(events)) continue;
      for (const event of events) {
        if (typeof event !== "object" || event === null) continue;
        const value = (event as Record<string, unknown>)["fixed"];
        if (typeof value === "string" && value !== "" && !fixed.includes(value)) fixed.push(value);
      }
    }
  }
  return fixed.slice(0, 10);
}

/**
 * Ask OSV about one Go module version.
 *
 * Never throws: every failure becomes an `unavailable` result carrying a
 * non-secret reason, and the profile decides what that means.
 */
export async function lookupVulnerabilities(
  modulePath: string,
  version: string,
  options: OsvOptions = {},
): Promise<VulnerabilityLookup> {
  const env = options.env ?? process.env;

  if (isPrivateModule(modulePath, env)) {
    return {
      kind: "not-applicable",
      reason: "the module is covered by GOPRIVATE/GONOPROXY and is never sent to a public database",
    };
  }

  // `GOPROXY=off` is the operator saying this machine does not talk to module
  // services. Honouring it for the proxy but not for OSV would be a surprise.
  if (resolveProxyBase(env) === undefined) {
    return { kind: "not-applicable", reason: "GOPROXY disables outbound module lookups" };
  }

  const doFetch = options.fetch ?? (globalThis.fetch as unknown as OsvFetch | undefined);
  if (doFetch === undefined) {
    return { kind: "unavailable", reason: "this runtime has no fetch implementation" };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, options.timeoutMs ?? OSV_TIMEOUT_MS);

  try {
    const response = await doFetch(options.endpoint ?? DEFAULT_OSV_ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        version,
        package: { name: modulePath, ecosystem: "Go" },
      }),
      signal: controller.signal,
    });

    if (!response.ok) {
      return { kind: "unavailable", reason: `OSV answered HTTP ${response.status}` };
    }

    const body = await response.text();
    if (body.length > MAX_RESPONSE_BYTES) {
      return { kind: "unavailable", reason: "OSV returned an implausibly large document" };
    }

    const parsed: unknown = JSON.parse(body);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return { kind: "unavailable", reason: "OSV returned an unexpected document" };
    }

    const vulns = (parsed as Record<string, unknown>)["vulns"];
    if (vulns === undefined) return { kind: "known", findings: [] };
    if (!Array.isArray(vulns)) {
      return { kind: "unavailable", reason: "OSV returned an unexpected document" };
    }

    const findings = vulns
      .slice(0, MAX_FINDINGS)
      .map(toFinding)
      .filter((finding): finding is VulnerabilityFinding => finding !== undefined);

    return { kind: "known", findings };
  } catch (error) {
    const detail =
      error instanceof Error && error.name === "AbortError"
        ? "OSV did not answer in time"
        : "OSV could not be reached";
    return { kind: "unavailable", reason: detail };
  } finally {
    clearTimeout(timer);
  }
}

export type { FetchLike };
