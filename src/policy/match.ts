/**
 * Local policy rule matching (M15): one call in, matched rules out.
 *
 * D9 (PLAN-LOCAL-POLICY): rules see the SAME wrapper-stripped, nested-shell
 * parsed view the adapters see (`generic/shell.ts`), and the SAME write-shape
 * semantics (`writtenPaths`). No second parser, no second convention -- a
 * second convention is a bypass waiting to be found.
 *
 * All match keys present on a rule must hold (AND). Matching is offline,
 * deterministic, and shape-only: paths and argv, never file content.
 */
import { relative } from "node:path";

import type { NormalizedToolCall } from "../core/events.ts";
import { commandName, parseShell, type SimpleCommand } from "../generic/shell.ts";
import {
  isWriteShapedToolCall,
  pathLikeInputValues,
  writtenPaths,
} from "../generic/sensitive-writes.ts";
import type { PolicyRule } from "./rules.ts";

export interface RuleMatch {
  readonly rule: PolicyRule;
  /** What matched, for the finding message. Never a secret. */
  readonly detail: string;
}

/**
 * `*` crosses nothing, `**` crosses everything, `?` one character. Written
 * here rather than pulled in: no dependency budget for a glob library, and a
 * policy glob grammar must stay this small on purpose.
 */
export function globToRegExp(pattern: string): RegExp {
  let source = "";
  for (let i = 0; i < pattern.length; i += 1) {
    const char = pattern[i];
    if (char === undefined) break;
    if (char === "*") {
      if (pattern[i + 1] === "*") {
        source += ".*";
        i += 1;
      } else {
        source += "[^/]*";
      }
    } else if (char === "?") {
      source += "[^/]";
    } else {
      source += char.replace(/[\\^$.+()[\]{}|]/g, "\\$&");
    }
  }
  return new RegExp(`^${source}$`);
}

/**
 * Collapse the shapes an agent uses to make a path look different:
 * `./a/b`, `a/../a/b`, and absolute paths inside the repository all reduce
 * to one comparable repository-relative form.
 */
export function normalizeOperand(value: string, repoRoot: string): string {
  let candidate = value.replace(/^\.\//, "");
  if (candidate.startsWith("/") || candidate.startsWith("~")) {
    const relativized = relative(repoRoot, candidate);
    // Inside the repository: compare in its own coordinates. Outside: the
    // absolute form is kept, honestly, and still starts with "/".
    if (!relativized.startsWith("..")) candidate = relativized;
  }
  const absolute = candidate.startsWith("/");
  // path.normalize collapses `a/../a`; POSIX only (backslash is not a
  // separator here, and a rule that needs it can match the raw text).
  const segments: string[] = [];
  for (const segment of candidate.split("/")) {
    if (segment === "." || segment === "") continue;
    if (segment === "..") {
      segments.pop();
      continue;
    }
    segments.push(segment);
  }
  return (absolute ? "/" : "") + segments.join("/");
}

function underPrefix(normalized: string, prefix: string): boolean {
  const trimmed = prefix.endsWith("/") ? prefix.slice(0, -1) : prefix;
  return normalized === trimmed || normalized.startsWith(`${trimmed}/`);
}

function pathOperands(command: SimpleCommand): readonly string[] {
  return command.argv
    .slice(1)
    .map((word) => word.text)
    .filter(
      (text) =>
        !text.startsWith("-") &&
        (text.includes("/") || /\.[A-Za-z0-9]+$/.test(text)),
    );
}

/**
 * Match `rules` against one tool call. Returns one entry per matched rule;
 * the caller folds them as findings with the rule's own decision.
 */
export function matchPolicyRules(
  call: NormalizedToolCall,
  rules: readonly PolicyRule[],
  repoRoot: string,
): readonly RuleMatch[] {
  if (rules.length === 0) return [];

  const rawCommand = call.input["command"];
  const commands =
    typeof rawCommand === "string" && rawCommand.trim() !== ""
      ? parseShell(rawCommand).commands
      : undefined;

  // One shared candidate pool per call: shell operands + redirections, and
  // file-tool path inputs. Normalized once, matched by every rule.
  const candidates: string[] = [];
  if (commands !== undefined) {
    for (const command of commands) {
      for (const operand of pathOperands(command)) candidates.push(operand);
      for (const write of command.writes ?? []) candidates.push(write);
    }
  }
  for (const value of pathLikeInputValues(call.input)) candidates.push(value);
  const normalized = [...new Set(candidates.map((value) => normalizeOperand(value, repoRoot)))];

  const matches: RuleMatch[] = [];
  for (const rule of rules) {
    const spec = rule.match;
    const held: string[] = [];

    if (spec.command !== undefined) {
      const hit =
        commands !== undefined &&
        commands.some((command) => {
          const head = command.argv[0];
          return head !== undefined && commandName(head.text) === spec.command;
        });
      if (!hit) continue;
      held.push(`command "${spec.command}"`);
    }

    if (spec.argsContain !== undefined) {
      const needles = spec.argsContain;
      const hit =
        commands !== undefined &&
        commands.some((command) =>
          command.argv.slice(1).some((word) => needles.some((needle) => word.text.includes(needle))),
        );
      if (!hit) continue;
      held.push(`argument containing ${needles.map((n) => `"${n}"`).join(" or ")}`);
    }

    if (spec.toolName !== undefined) {
      if (call.toolName !== spec.toolName) continue;
      held.push(`tool "${spec.toolName}"`);
    }

    const writePrefix = spec.writePrefix;
    if (writePrefix !== undefined) {
      // Reuse the write-shape semantics wholesale: sed -i, tee, cp/mv, dd,
      // redirections, git checkout -- and write-shaped file tools all count
      // as writes; a bare mention does not.
      const shellWrite = commands?.some(
        (command) => writtenPaths(command, [], [writePrefix]).length > 0,
      );
      const toolWrite =
        isWriteShapedToolCall(call.toolName) &&
        normalized.some((path) => underPrefix(path, writePrefix));
      if (shellWrite !== true && toolWrite !== true) continue;
      held.push(`write under ${writePrefix}`);
    }

    const readPrefix = spec.readPrefix;
    if (readPrefix !== undefined) {
      if (!normalized.some((path) => underPrefix(path, readPrefix))) continue;
      held.push(`access under ${readPrefix}`);
    }

    const pathGlob = spec.pathGlob;
    if (pathGlob !== undefined) {
      const pattern = globToRegExp(pathGlob);
      if (!normalized.some((path) => pattern.test(path))) continue;
      held.push(`path matching ${pathGlob}`);
    }

    matches.push({
      rule,
      detail: held.join(" + "),
    });
  }
  return matches;
}
