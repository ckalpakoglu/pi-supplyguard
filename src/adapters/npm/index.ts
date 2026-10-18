/**
 * The npm ecosystem adapter (M13).
 *
 * The threat model is the lifecycle script: `postinstall`/`preinstall` in a
 * dependency runs arbitrary code at install time, which is where the real npm
 * incidents lived. Commands are gated like Go's (shell-aware, exactness floor
 * for what floats); the lockfile diff names which module moved and, when the
 * lock records `hasInstallScript`, the dependency's own script body is read
 * from `node_modules` and shown to the human.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import type {
  AdapterContext,
  AdapterProjectStateResult,
  AdapterToolCallResult,
  EcosystemAdapter,
  ProjectStateContext,
} from "../registry.ts";
import type { NormalizedToolCall, SupplyChainEvent } from "../../core/events.ts";
import type { FileMutation } from "../../core/manifest.ts";
import { analyzeNpmCommand, NPM_ECOSYSTEM, type NpmEvent } from "./commands.ts";
import {
  diffDependencies,
  diffLock,
  lifecycleScripts,
  parsePackageJson,
  parsePackageLock,
} from "./modfile.ts";

export const PACKAGE_JSON = "package.json";
export const PACKAGE_LOCK = "package-lock.json";
export const SHRINKWRAP = "npm-shrinkwrap.json";

export const NPM_SENSITIVE_PATHS: readonly string[] = [
  PACKAGE_JSON,
  PACKAGE_LOCK,
  SHRINKWRAP,
  "pnpm-lock.yaml",
  "yarn.lock",
];

/** The node_modules tree is the npm vendor tree; hand-edits mean the same. */
export const NODE_MODULES_PREFIX = "node_modules/";

function toEvent(event: NpmEvent): SupplyChainEvent {
  return {
    eventClass: event.eventClass,
    ecosystem: NPM_ECOSYSTEM,
    classification: "THIRD_PARTY_MUTATION",
    summary: event.summary,
    ...(event.artifact === undefined ? {} : { artifact: event.artifact }),
    ...(event.version === undefined ? {} : { version: event.version }),
    ...(event.minimumDecision === undefined
      ? {}
      : { minimumDecision: event.minimumDecision }),
    ...(event.detail === undefined ? {} : { detail: event.detail }),
  };
}

function mutationEvent(
  eventClass: SupplyChainEvent["eventClass"],
  summary: string,
  extra: { artifact?: string; version?: string } = {},
): SupplyChainEvent {
  return {
    eventClass,
    ecosystem: NPM_ECOSYSTEM,
    classification: "THIRD_PARTY_MUTATION",
    summary,
    ...(extra.artifact === undefined ? {} : { artifact: extra.artifact }),
    ...(extra.version === undefined ? {} : { version: extra.version }),
  };
}

async function readText(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, "utf8");
  } catch {
    return undefined;
  }
}

/** The dependency's script body, if node_modules is already populated. */
async function installScriptBody(
  repoRoot: string,
  name: string,
): Promise<string | undefined> {
  const text = await readText(join(repoRoot, NODE_MODULES_PREFIX, name, PACKAGE_JSON));
  if (text === undefined) return undefined;
  const pkg = parsePackageJson(text);
  const scripts = lifecycleScripts(pkg);
  if (scripts.length === 0) return undefined;
  return scripts.map((s) => `${s}: ${pkg.scripts[s] ?? ""}`).join("\n");
}

export function createNpmAdapter(): EcosystemAdapter {
  return {
    id: NPM_ECOSYSTEM,

    sensitivePaths: () => NPM_SENSITIVE_PATHS,
    writeGuardPrefixes: () => [NODE_MODULES_PREFIX],

    inspectToolCall(call: NormalizedToolCall, _ctx: AdapterContext): AdapterToolCallResult {
      const raw = call.input["command"];
      if (typeof raw !== "string" || raw.trim() === "") {
        return { classification: "SUPPLY_CHAIN_IRRELEVANT", events: [] };
      }
      const analysis = analyzeNpmCommand(raw);
      return {
        classification: analysis.classification,
        events: analysis.events.map(toEvent),
        expectsManifestChange: analysis.writesLockfile,
      };
    },

    inspectFileMutation(
      mutation: FileMutation,
      ctx: AdapterContext,
    ): readonly SupplyChainEvent[] {
      if (!mutation.contentAvailable) {
        return [
          mutationEvent(
            "LockfileMutation",
            `${mutation.path} changed, but its content was too large to classify; ` +
              `treating the change as an unreviewed manifest mutation`,
          ),
        ];
      }

      if (mutation.path === PACKAGE_JSON) {
        if (!mutation.existsAfter) {
          return [mutationEvent("LockfileMutation", "package.json was deleted")];
        }
        const events: SupplyChainEvent[] = [];
        for (const change of diffDependencies(
          parsePackageJson(mutation.before ?? ""),
          parsePackageJson(mutation.after ?? ""),
        )) {
          const spec = change.to ?? change.from ?? "";
          events.push(
            mutationEvent(
              change.kind === "add"
                ? "DependencyAdd"
                : change.kind === "remove"
                  ? "DependencyRemove"
                  : change.kind === "upgrade"
                    ? "DependencyUpgrade"
                    : "DependencyDowngrade",
              `package.json ${change.kind}s ${change.name} ${spec} outside the SupplyGuard gate`,
              { artifact: change.name, version: spec },
            ),
          );
        }
        return events;
      }

      if (mutation.path === PACKAGE_LOCK || mutation.path === SHRINKWRAP) {
        const diff = diffLock(
          parsePackageLock(mutation.before ?? ""),
          parsePackageLock(mutation.after ?? ""),
        );
        if (
          diff.added.length === 0 &&
          diff.removed.length === 0 &&
          diff.changed.length === 0
        ) {
          // The file changed but no package moved: `resolved`/`integrity`
          // rewritten in place is exactly how a mirror substitution looks,
          // and nothing package-level would name it. Gate coarsely rather
          // than stay silent.
          return [
            mutationEvent(
              "LockfileMutation",
              `${mutation.path} changed outside the SupplyGuard gate with no package-level ` +
                `diff -- resolved URLs, integrity or metadata were rewritten in place`,
            ),
          ];
        }

        const names = [
          ...diff.added.map((e) => `${e.name}@${e.version ?? "?"}`),
          ...diff.changed.map(
            (c) => `${c.name}@${c.from ?? "?"}→${c.to ?? "?"}${c.hasInstallScript === true ? " (install script)" : ""}`,
          ),
        ];
        const shown = names.length > 5 ? [...names.slice(0, 5), `… +${names.length - 5} more`] : names;
        return [
          mutationEvent(
            "LockfileMutation",
            `the lockfile changed outside the SupplyGuard gate ` +
              `(${diff.added.length} package(s) added, ${diff.changed.length} changed, ` +
              `${diff.removed.length} removed)` +
              (shown.length === 0 ? "" : `: ${shown.join(", ")}`),
          ),
        ];
      }

      // pnpm/yarn lockfiles: gated coarsely, named honestly.
      return [
        mutationEvent("LockfileMutation", `${mutation.path} changed outside the SupplyGuard gate`),
      ];
    },

    /**
     * project-state time (on gated operations): every dependency the lockfile
     * marks `hasInstallScript` gets its script body read from `node_modules`
     * and shown. When `node_modules` is not populated yet, the flag alone is
     * the finding.
     */
    async inspectProjectState(ctx: ProjectStateContext): Promise<AdapterProjectStateResult> {
      if (ctx.classification === "SUPPLY_CHAIN_IRRELEVANT") return { events: [] };

      const lockText = await readText(join(ctx.repoRoot, PACKAGE_LOCK));
      if (lockText === undefined) return { events: [] };
      const entries = parsePackageLock(lockText);
      const events: SupplyChainEvent[] = [];
      const notes: string[] = [];

      for (const entry of entries) {
        if (entry.hasInstallScript !== true) continue;
        const body = await installScriptBody(ctx.repoRoot, entry.name);
        const eventClass = body === undefined ? "ToolInstall" : "ThirdPartyExecution";
        events.push({
          eventClass,
          ecosystem: NPM_ECOSYSTEM,
          classification: "THIRD_PARTY_MUTATION",
          artifact: entry.name,
          ...(entry.version === undefined ? {} : { version: entry.version }),
          summary:
            `${entry.name}@${entry.version ?? "?"} runs an install script (postinstall and ` +
            `friends) -- arbitrary code at install time` +
            (body === undefined ? "" : `:\n${body}`),
        });
        notes.push(`${entry.name} carries an install script`);
      }

      return events.length === 0 ? { events: [] } : { events, notes };
    },
  };
}
