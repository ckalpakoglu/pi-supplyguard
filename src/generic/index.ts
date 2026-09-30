/**
 * The generic policy adapter (SPEC 15, M8).
 *
 * Rules that belong to no ecosystem: installer pipelines, plain network
 * fetches, and GitHub Actions references. It is registered exactly like the Go
 * adapter, which is the point -- the engine still sees nothing but normalized
 * events from an opaque producer, and `curl … | sh` is denied whether or not
 * the repository contains a line of Go.
 */

import type {
  AdapterContext,
  AdapterProjectStateResult,
  AdapterToolCallResult,
  EcosystemAdapter,
  ProjectStateContext,
} from "../adapters/registry.ts";
import type { NormalizedToolCall, SupplyChainEvent } from "../core/events.ts";
import type { FileMutation } from "../core/manifest.ts";
import { readManifestSnapshot } from "../core/manifest.ts";
import {
  inspectWorkflow,
  isWorkflowPath,
  WORKFLOW_GLOBS,
} from "./github-actions.ts";
import {
  downloadTargets,
  executeOfDownloadedFile,
  GENERIC_ECOSYSTEM,
  inspectInstallers,
  inspectNetworkFetches,
} from "./installers.ts";
import { inspectSensitiveWrites } from "./sensitive-writes.ts";
import { parseShell } from "./shell.ts";

/**
 * Pull the shell command out of a tool call, by shape rather than tool name.
 */
function shellCommand(call: NormalizedToolCall): string | undefined {
  const command = call.input["command"];
  return typeof command === "string" && command.trim() !== "" ? command : undefined;
}

export function createGenericAdapter(): EcosystemAdapter {
  // M12: files this process watched being downloaded, by any earlier call.
  const downloadedFiles = new Set<string>();
  return {
    id: GENERIC_ECOSYSTEM,
    /** SPEC 14.1 lists workflow hashes in the snapshot set. */
    sensitivePaths: () => WORKFLOW_GLOBS,

    inspectToolCall(call: NormalizedToolCall, ctx: AdapterContext): AdapterToolCallResult {
      const command = shellCommand(call);
      if (command === undefined) {
        return { classification: "SUPPLY_CHAIN_IRRELEVANT", events: [] };
      }

      const parsed = parseShell(command);
      const pipelines = inspectInstallers(parsed.commands);
      const writes = inspectSensitiveWrites(
        parsed.commands,
        ctx.watchedPaths,
        ctx.writeGuardPrefixes ?? [],
      );
      for (const target of downloadTargets(parsed.commands)) downloadedFiles.add(target);
      // Correlation AFTER remembering: `curl -o i.sh …; sh i.sh` in one
      // command is the pipeline SPEC 15.2 denies, one separator later.
      const correlated = executeOfDownloadedFile(parsed.commands, downloadedFiles);
      const events = [
        ...pipelines,
        ...writes,
        ...correlated,
        ...inspectNetworkFetches(parsed.commands, pipelines.length),
      ];
      if (events.length === 0) {
        // An unreadable command is the Go adapter's safety net to raise, not
        // this one's: raising UNKNOWN_RISK here too would double-report the
        // same string and say nothing new.
        return { classification: "SUPPLY_CHAIN_IRRELEVANT", events: [] };
      }

      return {
        classification:
          pipelines.length > 0 || writes.length > 0 || correlated.length > 0
            ? "THIRD_PARTY_MUTATION"
            : "THIRD_PARTY_CAPABLE",
        events,
      };
    },

    /**
     * A workflow file rewritten outside the gate (SPEC 14, 15.1).
     *
     * Only the mutable references in the NEW content are reported: the point is
     * what CI will run next, not what it used to run.
     */
    inspectFileMutation(mutation: FileMutation, ctx: AdapterContext): readonly SupplyChainEvent[] {
      if (!isWorkflowPath(mutation.path)) return [];

      if (!mutation.existsAfter) {
        return [
          {
            eventClass: "CIReferenceChange",
            ecosystem: GENERIC_ECOSYSTEM,
            classification: "THIRD_PARTY_MUTATION",
            summary: `${mutation.path} was deleted; its CI supply-chain controls went with it`,
          },
        ];
      }

      if (!mutation.contentAvailable) {
        return [
          {
            eventClass: "CIReferenceChange",
            ecosystem: GENERIC_ECOSYSTEM,
            classification: "THIRD_PARTY_MUTATION",
            summary: `${mutation.path} changed but was too large to classify`,
          },
        ];
      }

      const before = new Set(
        inspectWorkflow(mutation.path, mutation.before ?? "", ctx.profile, {
          changed: true,
        }).map((event) => event.summary),
      );

      // A mutable reference that was already there is the repository's existing
      // state, not something this session did. Reporting it on every unrelated
      // workflow edit would train the operator to click through the gate.
      return inspectWorkflow(mutation.path, mutation.after ?? "", ctx.profile, {
        changed: true,
      }).filter((event) => !before.has(event.summary));
    },

    /**
     * Mutable references already committed to the repository.
     *
     * Reported once per gated operation rather than on every tool call: this is
     * standing state, and SPEC 4.4 gates it, but `ls` in a repository with a
     * `@v4` action is not an incident.
     */
    async inspectProjectState(ctx: ProjectStateContext): Promise<AdapterProjectStateResult> {
      if (ctx.classification === "SUPPLY_CHAIN_IRRELEVANT") return { events: [] };

      const snapshot = await readManifestSnapshot(ctx.repoRoot, WORKFLOW_GLOBS);
      const notes: string[] = [];

      for (const [path, file] of Object.entries(snapshot)) {
        if (file?.text === undefined) continue;
        for (const event of inspectWorkflow(path, file.text, ctx.profile, { changed: false })) {
          notes.push(event.summary);
        }
      }

      // Standing mutable references are recorded as evidence rather than
      // gating unrelated work; changing one is what produces an event.
      return notes.length === 0 ? { events: [] } : { events: [], notes };
    },
  };
}
