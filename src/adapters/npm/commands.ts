/**
 * npm command shapes (M13): shell-aware, no prefix matching.
 *
 * The exact-version rule is deliberately softer than the Go adapter's: `^1.2.3`
 * is the ecosystem's default, and denying it would make the adapter unusable
 * on arrival. What floats — a bare name, `*`, `latest`, `next` — carries the
 * same deny floor as Go's floating versions, because it means the same thing:
 * the registry decides what runs.
 */

import type { SupplyChainEventClass } from "../../core/events.ts";
import {
  commandName,
  parseShell,
  type ShellWord,
} from "../../generic/shell.ts";
import { isExactRange, isFloatingSpec } from "./modfile.ts";

export const NPM_ECOSYSTEM = "npm";

/** Package managers that share npm's command shapes closely enough. */
const MANAGERS = new Set(["npm", "pnpm", "yarn", "bun"]);
/** `npx`/`dlx` fetch-and-run a package on the spot. */
const RUNNERS = new Set(["npx", "dlx", "pnpm-dlx"]);

export interface NpmAnalysis {
  readonly classification:
    | "SUPPLY_CHAIN_IRRELEVANT"
    | "THIRD_PARTY_CAPABLE"
    | "THIRD_PARTY_MUTATION"
    | "UNKNOWN_RISK";
  readonly events: readonly NpmEvent[];
  readonly writesLockfile: boolean;
}

export interface NpmEvent {
  readonly eventClass: SupplyChainEventClass;
  readonly summary: string;
  readonly artifact?: string;
  readonly version?: string;
  readonly minimumDecision?: "ask" | "deny";
  readonly detail?: Record<string, string | number | boolean>;
}

function headWords(words: readonly ShellWord[]): string[] {
  return words.map((w) => w.text);
}

/** `npm install` alone, `npm i`, `yarn`, `yarn install`. */
function isBareInstall(manager: string, args: readonly string[]): boolean {
  const positional = args.filter((a) => !a.startsWith("-"));
  if (manager === "yarn" || manager === "bun") return positional.length === 0;
  const sub = positional[0];
  return (sub === "install" || sub === "i" || sub === "ci" || sub === "fresh") &&
    positional.length === 1;
}

export function analyzeNpmCommand(command: string): NpmAnalysis {
  const parsed = parseShell(command);
  const events: NpmEvent[] = [];
  let sawManager = false;
  let capable = false;

  for (const simple of parsed.commands) {
    const argv = headWords(simple.argv);
    const head = argv[0];
    if (head === undefined) continue;
    const tool = commandName(head);
    if (!MANAGERS.has(tool) && !RUNNERS.has(tool)) continue;

    sawManager = true;
    const args = argv.slice(1);

    if (tool === "npx" || (tool === "dlx" && head.includes("pnpm"))) {
      const target = args.find((a) => !a.startsWith("-"));
      if (target !== undefined) {
        const at = target.lastIndexOf("@");
        events.push({
          eventClass: "ThirdPartyExecution",
          summary: `fetches and runs ${target} on the spot through ${tool}`,
          artifact: at > 0 ? target.slice(0, at) : target,
          ...(at > 0 ? { version: target.slice(at + 1) } : {}),
        });
      }
      continue;
    }

    const positional = args.filter((a) => !a.startsWith("-"));
    const sub = positional[0];

    // `npm run <script>` executes repo-defined scripts: capable, not an event;
    // the scripts that matter are the dependencies', and those surface through
    // the lockfile.
    if (sub === "run" || sub === "test" || sub === "start" || sub === "exec") {
      capable = true;
      continue;
    }

    const global = args.some((a) => a === "-g" || a === "--global");
    const isAdd = sub === "install" || sub === "i" || sub === "add" || isBareInstall(tool, args);
    const isRemove = sub === "uninstall" || sub === "remove" || sub === "rm";

    if (isAdd) {
      const targets = positional.slice(sub === undefined ? 0 : 1).filter((t) => !t.startsWith("-"));
      if (global) {
        for (const target of targets) {
          const { name, spec } = splitSpec(target);
          events.push({
            eventClass: "ToolInstall",
            summary: `installs ${target} globally through ${tool}`,
            artifact: name,
            ...(spec !== undefined ? { version: spec } : {}),
            ...(spec === undefined ? { minimumDecision: "deny" as const } : {}),
          });
        }
        continue;
      }
      if (targets.length === 0) {
        // Bare install/ci: reconciles the lockfile and RUNS dependency
        // lifecycle scripts -- the npm threat model, gated as a lockfile
        // mutation rather than a specific artifact.
        events.push({
          eventClass: "LockfileMutation",
          summary:
            `${tool} ${sub ?? "install"} reconciles the lockfile and runs dependency ` +
            `lifecycle scripts (postinstall and friends), which is arbitrary code at ` +
            `install time`,
        });
        continue;
      }
      for (const target of targets) {
        const { name, spec } = splitSpec(target);
        events.push({
          eventClass: "DependencyAdd",
          summary: `adds ${target} through ${tool}`,
          artifact: name,
          ...(spec !== undefined ? { version: spec } : {}),
          ...(floatingFloor(spec) ? { minimumDecision: "deny" as const } : {}),
          ...(spec !== undefined && !isExactRange(spec) && !isFloatingSpec(spec)
            ? { detail: { range: spec } }
            : {}),
        });
      }
      continue;
    }

    if (isRemove) {
      for (const target of positional.slice(1)) {
        events.push({
          eventClass: "DependencyRemove",
          summary: `removes ${target} through ${tool}`,
          artifact: target,
        });
      }
      continue;
    }

    // Anything else manager-shaped can still touch the graph or run code.
    capable = true;
  }

  if (!sawManager) return { classification: "SUPPLY_CHAIN_IRRELEVANT", events: [], writesLockfile: false };

  const mutation = events.some(
    (e) =>
      e.eventClass === "DependencyAdd" ||
      e.eventClass === "DependencyRemove" ||
      e.eventClass === "LockfileMutation" ||
      e.eventClass === "ToolInstall" ||
      e.eventClass === "ThirdPartyExecution",
  );
  return {
    classification: mutation ? "THIRD_PARTY_MUTATION" : capable ? "THIRD_PARTY_CAPABLE" : "SUPPLY_CHAIN_IRRELEVANT",
    events,
    writesLockfile: events.some((e) => e.eventClass === "LockfileMutation" || e.eventClass === "DependencyAdd"),
  };
}

function splitSpec(target: string): { name: string; spec?: string } {
  const trimmed = target.replace(/^@?/, "");
  // Scoped names carry a leading @ that the last @ split must respect.
  const at = trimmed.lastIndexOf("@");
  if (at <= 0) return { name: trimmed };
  return { name: trimmed.slice(0, at), spec: trimmed.slice(at + 1) };
}

function floatingFloor(spec: string | undefined): boolean {
  return spec === undefined || isFloatingSpec(spec);
}
