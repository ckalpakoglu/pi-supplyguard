/**
 * The Go ecosystem adapter (SPEC 7, 10; milestone M2).
 *
 * This is the only place in the codebase that knows what `go get` means. It
 * translates command-shaped tool calls into normalized events and hands them
 * to the ecosystem-agnostic engine, which decides.
 *
 * DELEGATION NOTE (human decision, 2026-09-01)
 * --------------------------------------------
 * Dependency mutations are Chief-only. A delegated worker runs headless, a
 * THIRD_PARTY_MUTATION produces an ASK, and a headless ASK fails closed
 * (SPEC 17.1). So a worker simply cannot add or upgrade a Go dependency; the
 * Chief performs that trust decision with a human present. This needs no code
 * here -- it is what the engine already does -- but it is load-bearing
 * behavior, so `test/go/adapter.test.ts` pins it. Brokered or pre-scoped
 * worker approval is deferred to M4.
 *
 * SCOPE: M2 was the command gate only. M3 adds the other half of SPEC 14 --
 * the file mutations a command gate structurally cannot see (`sed`, Python, a
 * generated script) become semantic events through `inspectFileMutation`, and
 * the vendor model becomes enforceable through `inspectProjectState`.
 */

import type {
  AdapterContext,
  AdapterProjectStateResult,
  AdapterToolCallResult,
  EcosystemAdapter,
  ProjectDecisionContext,
  ProjectDecisionRequest,
  ProjectStateContext,
} from "../registry.ts";
import type { NormalizedToolCall, SupplyChainEvent } from "../../core/events.ts";
import type { FileMutation } from "../../core/manifest.ts";
import { analyzeCommand, GO_ECOSYSTEM, type GoOperation } from "./commands.ts";
import {
  diffGoMod,
  diffGoSum,
  isLocalReplaceTarget,
  parseGoMod,
  parseGoSum,
  type GoModChange,
} from "./modfile.ts";
import {
  detectGoProject,
  GO_MOD,
  GO_SENSITIVE_PATHS,
  GO_SUM,
  VENDOR_MODULES,
  VENDOR_PREFIX,
} from "./project.ts";
import { lookupVulnerabilities, type OsvOptions } from "./osv.ts";
import { lookupReleaseDate, type ProxyOptions } from "./proxy.ts";
import type { ReleaseLookup } from "../../core/release-age.ts";
import type { VulnerabilityLookup } from "../../core/vulnerability.ts";

/**
 * Pull the shell command out of a tool call.
 *
 * Keyed on the shape of the input rather than on a hard-coded tool name: Pi's
 * bash tool passes `command`, and keying on the field means a renamed or
 * additional command-shaped tool is still inspected. A tool call without one
 * is not a command and is not this adapter's business.
 */
function shellCommand(call: NormalizedToolCall): string | undefined {
  const command = call.input["command"];
  return typeof command === "string" && command.trim() !== "" ? command : undefined;
}

function toEvent(operation: GoOperation): SupplyChainEvent {
  return {
    eventClass: operation.eventClass,
    ecosystem: GO_ECOSYSTEM,
    classification: operation.classification,
    summary: operation.summary,
    ...(operation.artifact === undefined ? {} : { artifact: operation.artifact }),
    ...(operation.version === undefined ? {} : { version: operation.version }),
    ...(operation.minimumDecision === undefined
      ? {}
      : { minimumDecision: operation.minimumDecision }),
    // Marks `go mod vendor` so project-state inspection does not deny the one
    // command that makes a stale vendor tree current again.
    ...(operation.refreshesVendor === true ? { detail: { refreshesVendor: true } } : {}),
  };
}

/** Project decision id for the SPEC 9.2 vendor-model question. */
export const VENDOR_MODE_DECISION = "go.vendorMode";
export const VENDOR_ENFORCE = "enforce";
export const VENDOR_OPTIONAL = "optional";

function mutationEvent(
  eventClass: SupplyChainEvent["eventClass"],
  summary: string,
  extra: {
    readonly artifact?: string;
    readonly version?: string;
    readonly minimumDecision?: SupplyChainEvent["minimumDecision"];
    readonly detail?: SupplyChainEvent["detail"];
  } = {},
): SupplyChainEvent {
  return {
    eventClass,
    ecosystem: GO_ECOSYSTEM,
    // An observed manifest change IS a third-party trust mutation, whatever
    // the tool call that produced it was classified as (SPEC 14).
    classification: "THIRD_PARTY_MUTATION",
    summary,
    ...(extra.artifact === undefined ? {} : { artifact: extra.artifact }),
    ...(extra.version === undefined ? {} : { version: extra.version }),
    ...(extra.minimumDecision === undefined
      ? {}
      : { minimumDecision: extra.minimumDecision }),
    ...(extra.detail === undefined ? {} : { detail: extra.detail }),
  };
}

/** Translate one semantic `go.mod` change into a normalized event (SPEC 10.5). */
function goModChangeEvent(change: GoModChange): SupplyChainEvent {
  switch (change.kind) {
    case "add":
      return mutationEvent(
        "DependencyAdd",
        `go.mod now requires ${change.require.path} ${change.require.version}, ` +
          `added outside the SupplyGuard gate`,
        { artifact: change.require.path, version: change.require.version },
      );
    case "upgrade":
      return mutationEvent(
        "DependencyUpgrade",
        `go.mod moved ${change.require.path} from ${change.from} to ${change.require.version} ` +
          `outside the SupplyGuard gate`,
        { artifact: change.require.path, version: change.require.version },
      );
    case "downgrade":
      return mutationEvent(
        "DependencyDowngrade",
        `go.mod moved ${change.require.path} back from ${change.from} to ` +
          `${change.require.version} outside the SupplyGuard gate`,
        { artifact: change.require.path, version: change.require.version },
      );
    case "remove":
      return mutationEvent(
        "DependencyRemove",
        `go.mod no longer requires ${change.path} (was ${change.fromVersion})`,
        { artifact: change.path, version: change.fromVersion },
      );
    case "indirect-flag":
      return mutationEvent(
        "LockfileMutation",
        `go.mod re-marked ${change.require.path} as ` +
          `${change.require.indirect ? "indirect" : "a direct requirement"}`,
        { artifact: change.require.path, version: change.require.version },
      );
    case "replace-add":
    case "replace-change": {
      const remote = !isLocalReplaceTarget(change.replace.to);
      return mutationEvent(
        "DependencyReplace",
        // SPEC 10.5: a remote replace redirects a module to third-party code
        // and is higher risk than a local development replace.
        `go.mod ${change.kind === "replace-add" ? "adds" : "changes"} a ` +
          `${remote ? "REMOTE" : "local"} replace of ${change.replace.from} => ` +
          `${change.replace.to}${change.replace.version === undefined ? "" : ` ${change.replace.version}`}`,
        {
          artifact: change.replace.from,
          detail: { target: change.replace.to, remote },
          ...(change.replace.version === undefined ? {} : { version: change.replace.version }),
        },
      );
    }
    case "replace-remove":
      return mutationEvent("DependencyReplace", `go.mod removes the replace of ${change.from}`, {
        artifact: change.from,
      });
    case "exclude-add":
      return mutationEvent(
        "LockfileMutation",
        `go.mod excludes ${change.exclude.path} ${change.exclude.version}`,
        { artifact: change.exclude.path, version: change.exclude.version },
      );
    case "exclude-remove":
      return mutationEvent("LockfileMutation", `go.mod no longer excludes ${change.path}`, {
        artifact: change.path,
      });
    case "other":
      return mutationEvent("LockfileMutation", `go.mod changed: ${change.summary}`);
  }
}

function goModEvents(mutation: FileMutation): readonly SupplyChainEvent[] {
  if (!mutation.existsAfter) {
    return [
      mutationEvent(
        "LockfileMutation",
        "go.mod was deleted; the project's dependency requirements are gone",
      ),
    ];
  }

  const diff = diffGoMod(
    parseGoMod(mutation.before ?? ""),
    parseGoMod(mutation.after ?? ""),
  );
  // A hash change with no semantic change is reformatting or a comment edit.
  // Reporting it as a dependency event would be false; reporting nothing is
  // correct, because the parser accounted for every line.
  return diff.changes.map(goModChangeEvent);
}

function goSumEvents(mutation: FileMutation): readonly SupplyChainEvent[] {
  if (!mutation.existsAfter) {
    // Deleting go.sum removes the checksums Go verifies downloads against.
    // That is an integrity-control bypass, not bookkeeping (SPEC 10.3).
    return [
      mutationEvent(
        "ChecksumBypass",
        "go.sum was deleted, removing the checksums Go verifies module downloads against",
        { minimumDecision: "deny" },
      ),
    ];
  }

  const diff = diffGoSum(parseGoSum(mutation.before ?? ""), parseGoSum(mutation.after ?? ""));
  if (diff.added.length === 0 && diff.removed.length === 0) return [];
  return [
    mutationEvent(
      "LockfileMutation",
      `go.sum changed outside the SupplyGuard gate ` +
        `(${diff.added.length} line(s) added, ${diff.removed.length} removed)`,
      { detail: { added: diff.added.length, removed: diff.removed.length } },
    ),
  ];
}

/**
 * Classify an observed change to a tracked Go file.
 *
 * This is the half of SPEC 14 that command interception cannot reach. The
 * events produced here are indistinguishable, to the engine, from the ones the
 * command gate produces -- which is the point: `sed -i go.mod` and
 * `go get` reach the same trust decision.
 */
function inspectGoFileMutation(mutation: FileMutation): readonly SupplyChainEvent[] {
  if (!mutation.contentAvailable) {
    return [
      mutationEvent(
        "LockfileMutation",
        `${mutation.path} changed, but its content was too large to classify; ` +
          `treating the change as an unreviewed manifest mutation`,
      ),
    ];
  }

  if (mutation.path === GO_MOD) return goModEvents(mutation);
  if (mutation.path === GO_SUM) return goSumEvents(mutation);
  if (mutation.path === VENDOR_MODULES) {
    return [
      mutationEvent(
        "LockfileMutation",
        `${VENDOR_MODULES} changed outside the SupplyGuard gate; the vendor tree no ` +
          `longer necessarily reflects a reviewed dependency graph`,
      ),
    ];
  }
  // go.work / go.work.sum: workspace-level requirements and checksums.
  return [
    mutationEvent(
      "LockfileMutation",
      `${mutation.path} changed outside the SupplyGuard gate`,
    ),
  ];
}

/**
 * @param proxy injectable proxy access. Tests pass a fake; nothing in the test
 * suite is allowed to reach the network.
 */
export function createGoAdapter(
  proxy: ProxyOptions = {},
  osv: OsvOptions = { ...(proxy.env === undefined ? {} : { env: proxy.env }) },
): EcosystemAdapter {
  const releaseDates = new Map<string, ReleaseLookup>();
  const vulnerabilities = new Map<string, VulnerabilityLookup>();

  return {
    id: GO_ECOSYSTEM,

    /**
     * SPEC 11.1 -- when was this version published?
     *
     * Cached for the process: a published version's date never changes, and
     * re-asking on every gated operation would be a needless request and a
     * needless disclosure.
     */
    async resolveReleaseDate(artifact: string, version: string): Promise<ReleaseLookup> {
      const key = `${artifact}@${version}`;
      const cached = releaseDates.get(key);
      if (cached !== undefined) return cached;

      const lookup = await lookupReleaseDate(artifact, version, proxy);
      releaseDates.set(key, lookup);
      return lookup;
    },

    /**
     * SPEC 16 -- known vulnerabilities, from OSV.
     *
     * Cached per process like the release date. Advisories DO change, unlike a
     * publication date, but re-querying within a single session would trade a
     * disclosure and a round trip for a freshness nobody needs mid-task.
     */
    async resolveVulnerabilities(
      artifact: string,
      version: string,
    ): Promise<VulnerabilityLookup> {
      const key = `${artifact}@${version}`;
      const cached = vulnerabilities.get(key);
      if (cached !== undefined) return cached;

      const lookup = await lookupVulnerabilities(artifact, version, osv);
      vulnerabilities.set(key, lookup);
      return lookup;
    },

    sensitivePaths: () => GO_SENSITIVE_PATHS,

    /**
     * Vendored SOURCE is the one Go input that is executed by enforced builds
     * but not snapshotted (hashing a vendor tree per call costs more than the
     * attacker's path is worth). Direct writes into it are gated by command
     * shape instead; `go mod vendor` itself names no file operand, so the
     * legitimate refresher is not caught.
     */
    writeGuardPrefixes: () => [VENDOR_PREFIX],

    inspectFileMutation: (mutation: FileMutation) => inspectGoFileMutation(mutation),

    /**
     * SPEC 9.2 -- ask ONCE whether to keep enforcing an existing vendor model.
     *
     * Only asked when a vendor tree exists: there is nothing to keep enforcing
     * otherwise. Paranoid does not ask, because it has no weakening choice to
     * offer (SPEC 4.3).
     */
    async projectDecisions(
      ctx: ProjectDecisionContext,
    ): Promise<readonly ProjectDecisionRequest[]> {
      if (ctx.profile === "paranoid") return [];
      if (ctx.decisions[VENDOR_MODE_DECISION] !== undefined) return [];

      const project = await detectGoProject(ctx.repoRoot);
      if (!project.hasVendorTree) return [];

      return [
        {
          id: VENDOR_MODE_DECISION,
          question:
            "SupplyGuard — vendored Go dependencies detected.\n\n" +
            "Continue enforcing the repository vendor model?",
          options: [
            { label: "Yes — keep enforcing vendoring", value: VENDOR_ENFORCE },
            { label: "No — do not enforce vendoring", value: VENDOR_OPTIONAL },
          ],
          recommended: VENDOR_ENFORCE,
          // No human, no weakening: the repository already vendors, so the
          // conservative answer is to keep its model.
          headlessValue: VENDOR_ENFORCE,
          headlessNote:
            "headless session: kept enforcing the existing Go vendor model without asking",
        },
      ];
    },

    async describe(ctx: ProjectDecisionContext): Promise<readonly string[]> {
      const project = await detectGoProject(ctx.repoRoot);
      if (!project.isGoProject) return ["go: no Go project detected"];

      const enforced =
        ctx.profile === "paranoid" ||
        (project.hasVendorTree && ctx.decisions[VENDOR_MODE_DECISION] !== VENDOR_OPTIONAL);

      const lines = [
        `go: go.mod ${project.hasGoMod ? "present" : "absent"}, ` +
          `go.sum ${project.hasGoSum ? "present" : "absent"}` +
          `${project.hasGoWork ? ", go.work present" : ""}`,
        `go: vendor ${project.vendorState} (${enforced ? "enforced" : "not enforced"})`,
      ];
      for (const reason of project.driftReasons) lines.push(`go:   drift — ${reason}`);
      return lines;
    },

    /**
     * Vendor state (SPEC 9.3, 9.4).
     *
     * Drift is derived from `go.mod` versus `vendor/modules.txt` on disk, so it
     * survives a restart and reflects out-of-band edits.
     */
    async inspectProjectState(ctx: ProjectStateContext): Promise<AdapterProjectStateResult> {
      const project = await detectGoProject(ctx.repoRoot);
      if (!project.isGoProject) return { events: [] };

      const events: SupplyChainEvent[] = [];
      const notes: string[] = [];

      const enforced =
        ctx.profile === "paranoid" ||
        (project.hasVendorTree &&
          ctx.decisions[VENDOR_MODE_DECISION] !== VENDOR_OPTIONAL);

      // `go mod vendor` IS the remedy. Denying it because the tree it is about
      // to rewrite is stale would leave the repository with no way forward but
      // editing configuration, which SPEC 17.2 rules out as an override. The
      // command still passes the normal gate on its own merits: it is a
      // THIRD_PARTY_MUTATION and therefore asks.
      const repairsVendor = ctx.events.some(
        (event) =>
          event.ecosystem === GO_ECOSYSTEM && event.detail?.["refreshesVendor"] === true,
      );

      if (enforced && project.vendorState === "stale" && repairsVendor) {
        notes.push(
          `the vendor tree is stale (${project.driftReasons.join("; ")}); this command ` +
            `refreshes it`,
        );
      } else if (enforced && project.vendorState === "stale") {
        events.push({
          eventClass: "VendorDrift",
          ecosystem: GO_ECOSYSTEM,
          classification: "THIRD_PARTY_CAPABLE",
          summary:
            `the vendor tree no longer matches go.mod: ${project.driftReasons.join("; ")}. ` +
            `Run \`go mod vendor\` to make the vendored code match the reviewed graph.`,
          detail: { reasons: project.driftReasons.length },
        });
      }

      if (project.hasGoMod && !project.hasVendorTree) {
        if (ctx.profile === "paranoid" && ctx.classification === "THIRD_PARTY_MUTATION") {
          // SPEC 9.3: paranoid denies a dependency-changing operation until
          // vendoring is established. Build and test are left alone -- the gate
          // is on mutation, not on working in the repository.
          events.push({
            eventClass: "VendorDrift",
            ecosystem: GO_ECOSYSTEM,
            classification: "THIRD_PARTY_MUTATION",
            summary:
              "paranoid requires a vendored dependency tree before dependency-changing " +
              "operations; this repository has no vendor/modules.txt",
            minimumDecision: "deny",
          });
        } else if (ctx.profile === "hardened") {
          // SPEC 9.3 hardened: recommend vendoring, allow continuing without
          // it. SupplyGuard does not run `go mod vendor`, so the recommendation
          // is recorded as audit evidence rather than dressed up as a gate.
          notes.push(
            "hardened profile: this Go project is not vendored; `go mod vendor` would let " +
              "builds and tests run from reviewed code",
          );
        }
      }

      return notes.length === 0 ? { events } : { events, notes };
    },

    inspectToolCall(call: NormalizedToolCall, _ctx: AdapterContext): AdapterToolCallResult {
      const command = shellCommand(call);
      if (command === undefined) {
        return { classification: "SUPPLY_CHAIN_IRRELEVANT", events: [] };
      }

      const analysis = analyzeCommand(command);
      const events = analysis.operations.map(toEvent);

      // An unreadable command is unknown risk, not absence of risk. The
      // classification alone carries that: the engine's UNKNOWN_RISK baseline
      // is ask / ask / deny, which is SPEC 5.1's "fail conservative according
      // to the active profile". Do NOT synthesize an event for it -- event
      // classes such as SecurityBypass deny in every profile and would flatten
      // that gradation.
      //
      return {
        classification: analysis.classification,
        events,
        expectsManifestChange: analysis.writesManifests,
        ...(analysis.notes.length === 0 ? {} : { notes: analysis.notes }),
      };
    },
  };
}
