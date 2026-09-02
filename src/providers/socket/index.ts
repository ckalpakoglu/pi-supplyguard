/**
 * Socket.dev as an external intelligence provider (SPEC 13, 20).
 *
 * Socket is ADDITIVE. It reaches the decision through `withExternalEvidence`,
 * which is structurally incapable of weakening a local one: a clean Socket
 * result cannot turn a reposquat, a GOSUMDB bypass or a release-age denial into
 * an allow (SPEC 13.5). It can only ever add a reason to refuse.
 *
 * SCOPE (human decision, 2026-09-02): the Socket CLI, not Socket Firewall.
 * `socket package score` gives artifact-level intelligence with no deployment
 * to stand up. Firewall -- SPEC 13.3's ask-once Hardened prompt and 13.4's
 * mandatory protected fetch for Paranoid -- is therefore NOT implemented, and
 * `docs/KNOWN-GAPS.md` says so rather than letting Paranoid look complete.
 */

import type { ExternalFinding } from "../../core/decisions.ts";
import { externalFinding } from "../../core/decisions.ts";
import type { SupplyChainEvent } from "../../core/events.ts";
import { needsJustification } from "../../core/justification.ts";
import type { Profile } from "../../core/profiles.ts";
import { parseSeverity, type Severity } from "../../core/vulnerability.ts";
import { createSocketRunner, type SocketCliOptions, type SocketRunner } from "./cli.ts";

export const SOCKET_PROVIDER_ID = "socket";

/** Ecosystem ids SupplyGuard knows how to name in a purl. */
const PURL_ECOSYSTEM: Readonly<Record<string, string>> = { go: "golang" };

/**
 * Build the package URL Socket expects.
 *
 * `pkg:golang/github.com/foo/bar@v1.2.3` -- the CLI's own help uses exactly
 * this form for Go.
 */
export function toPurl(ecosystem: string, artifact: string, version: string): string | undefined {
  const scheme = PURL_ECOSYSTEM[ecosystem];
  if (scheme === undefined) return undefined;
  return `pkg:${scheme}/${artifact}@${version}`;
}

export interface SocketAlert {
  readonly name: string;
  readonly severity: Severity;
}

export type SocketArtifactResult =
  | { readonly kind: "scanned"; readonly alerts: readonly SocketAlert[]; readonly overall?: number }
  | { readonly kind: "unsupported"; readonly reason: string }
  | { readonly kind: "unavailable"; readonly reason: string };

/**
 * Interpret `socket package score --json`.
 *
 * The document is `{ ok, data: { self: { score, alerts }, transitively: {...} } }`.
 * Anything else is `unavailable`: an unrecognized shape must never be read as a
 * clean result, because "we could not tell" and "there is nothing wrong" are
 * the two answers a security tool must never confuse.
 */
export function parseScoreDocument(text: string): SocketArtifactResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { kind: "unavailable", reason: "the socket CLI did not return a JSON document" };
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { kind: "unavailable", reason: "the socket CLI returned an unexpected document" };
  }

  const document = parsed as Record<string, unknown>;
  if (document["ok"] !== true) {
    const message = document["message"];
    const cause = document["cause"];
    const detail = [message, cause].filter((part) => typeof part === "string").join(": ");
    return {
      kind: "unavailable",
      reason: detail === "" ? "the socket CLI reported a failure" : detail.slice(0, 300),
    };
  }

  const data = document["data"];
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    return { kind: "unavailable", reason: "the socket CLI returned no score data" };
  }

  const alerts: SocketAlert[] = [];
  let overall: number | undefined;

  for (const section of ["self", "transitively"] as const) {
    const value = (data as Record<string, unknown>)[section];
    if (typeof value !== "object" || value === null) continue;
    const record = value as Record<string, unknown>;

    const rawAlerts = record["alerts"];
    if (Array.isArray(rawAlerts)) {
      for (const alert of rawAlerts) {
        if (typeof alert !== "object" || alert === null) continue;
        const name = (alert as Record<string, unknown>)["name"];
        if (typeof name !== "string" || name === "") continue;
        alerts.push({
          name: name.slice(0, 120),
          severity: readAlertSeverity((alert as Record<string, unknown>)["severity"]),
        });
      }
    }

    const score = record["score"];
    if (section === "self" && typeof score === "object" && score !== null) {
      const value2 = (score as Record<string, unknown>)["overall"];
      if (typeof value2 === "number" && Number.isFinite(value2)) overall = value2;
    }
  }

  return { kind: "scanned", alerts, ...(overall === undefined ? {} : { overall }) };
}

/** Socket spells its middle band `middle`; everything else matches OSV's. */
export function readAlertSeverity(value: unknown): Severity {
  if (typeof value === "string" && value.trim().toLowerCase() === "middle") return "moderate";
  return parseSeverity(value);
}

export interface SocketProviderOptions extends SocketCliOptions {
  /**
   * `required` makes an unavailable provider a denial (SPEC 13.4). Paranoid
   * sets it regardless of configuration.
   */
  readonly required?: boolean;
}

export interface SocketProvider {
  /** SPEC 20 -- a provider that cannot pass its own health check authorizes nothing. */
  health(): Promise<{ readonly ok: boolean; readonly version?: string; readonly reason?: string }>;
  checkArtifact(
    ecosystem: string,
    artifact: string,
    version: string,
  ): Promise<SocketArtifactResult>;
}

export function createSocketProvider(options: SocketProviderOptions = {}): SocketProvider {
  const run: SocketRunner = createSocketRunner(options);
  let healthCache: { ok: boolean; version?: string; reason?: string } | undefined;
  const artifacts = new Map<string, SocketArtifactResult>();

  return {
    async health() {
      if (healthCache !== undefined) return healthCache;

      const result = await run(["--version"]);
      const version = result.stdout.trim().split(/\s+/)[0];
      healthCache =
        result.ok && version !== undefined && version !== ""
          ? { ok: true, version }
          : {
              ok: false,
              reason: result.reason ?? "the socket CLI did not report a version",
            };
      return healthCache;
    },

    async checkArtifact(ecosystem, artifact, version) {
      const purl = toPurl(ecosystem, artifact, version);
      if (purl === undefined) {
        return { kind: "unsupported", reason: `socket has no purl mapping for "${ecosystem}"` };
      }

      const cached = artifacts.get(purl);
      if (cached !== undefined) return cached;

      const result = await run(["package", "score", purl, "--json"]);
      const parsed =
        result.stdout.trim() === ""
          ? ({
              kind: "unavailable",
              reason: result.reason ?? "the socket CLI returned no output",
            } as const)
          : parseScoreDocument(result.stdout);

      artifacts.set(purl, parsed);
      return parsed;
    },
  };
}

/**
 * Turn one artifact result into external findings.
 *
 * Every finding here is `external`, so it can only tighten. Socket denials are
 * deliberately NOT overridable: the local checks own the judgement calls, and
 * SPEC 17.3 is explicit that provider trouble must not become a routine
 * exception.
 */
export function socketFindings(
  result: SocketArtifactResult,
  options: { readonly profile: Profile; readonly artifact: string; readonly version: string; readonly required: boolean },
): readonly ExternalFinding[] {
  const { profile, artifact, version, required } = options;
  const subject = `${artifact}@${version}`;

  if (result.kind === "unsupported") {
    return required
      ? [
          externalFinding(
            SOCKET_PROVIDER_ID,
            "socket-unsupported",
            "deny",
            `Socket cannot evaluate ${subject} (${result.reason}), and this profile requires ` +
              `an artifact evaluation for every new dependency.`,
          ),
        ]
      : [];
  }

  if (result.kind === "unavailable") {
    return [
      externalFinding(
        SOCKET_PROVIDER_ID,
        "socket-unavailable",
        required ? "deny" : "warn",
        `Socket could not evaluate ${subject} (${result.reason}).` +
          (required
            ? ` This profile requires it; restore Socket or change the profile deliberately.`
            : ``),
      ),
    ];
  }

  const findings: ExternalFinding[] = [];
  const worst = result.alerts.reduce<Severity>(
    (highest, alert) => (rank(alert.severity) > rank(highest) ? alert.severity : highest),
    "low",
  );

  if (result.alerts.length === 0) {
    return findings;
  }

  const named = result.alerts
    .filter((alert) => alert.severity === worst)
    .slice(0, 5)
    .map((alert) => alert.name)
    .join(", ");
  const detail = `Socket reported ${result.alerts.length} alert(s) for ${subject}, worst ${worst}: ${named}`;

  const decision =
    worst === "critical"
      ? "deny"
      : worst === "high"
        ? profile === "paranoid"
          ? "deny"
          : "ask"
        : worst === "unknown"
          ? profile === "paranoid"
            ? "ask"
            : "warn"
          : "warn";

  findings.push(externalFinding(SOCKET_PROVIDER_ID, `socket-alert:${worst}`, decision, detail));
  return findings;
}

function rank(severity: Severity): number {
  return { low: 0, moderate: 1, unknown: 2, high: 3, critical: 4 }[severity];
}

/**
 * The engine-facing hook (SPEC 13.5).
 *
 * Health is checked once per session before anything is trusted: SPEC 20 says a
 * provider that cannot pass its own version check cannot authorize a new
 * dependency trust decision.
 */
export function createSocketEvidence(
  provider: SocketProvider,
  options: { readonly requiredFor: (profile: Profile) => boolean },
) {
  return async (
    events: readonly SupplyChainEvent[],
    ctx: { readonly profile: Profile },
  ): Promise<readonly ExternalFinding[]> => {
    const subjects = events.filter(needsJustification);
    if (subjects.length === 0) return [];

    const required = options.requiredFor(ctx.profile);
    const health = await provider.health();
    if (!health.ok) {
      return [
        externalFinding(
          SOCKET_PROVIDER_ID,
          "socket-health",
          required ? "deny" : "warn",
          `Socket did not pass its own health check (${health.reason ?? "unknown"}), so it ` +
            `cannot vouch for anything.` +
            (required ? ` This profile requires a working Socket integration.` : ``),
        ),
      ];
    }

    const findings: ExternalFinding[] = [];
    for (const event of subjects) {
      const result = await provider.checkArtifact(
        event.ecosystem,
        event.artifact ?? "",
        event.version ?? "",
      );
      findings.push(
        ...socketFindings(result, {
          profile: ctx.profile,
          artifact: event.artifact ?? "",
          version: event.version ?? "",
          required,
        }),
      );
    }
    return findings;
  };
}
