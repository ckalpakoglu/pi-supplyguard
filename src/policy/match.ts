/**
 * Local policy rule matching (M15): one tool call in, the rules it trips out.
 *
 * Rules see the SAME parsed view the adapters see -- wrapper-stripped,
 * nested `sh -c` unwrapped (`generic/shell.ts`) -- and the SAME write shapes
 * (`writtenPaths`). A second convention would be a bypass waiting to happen.
 * Every key on a rule must hold. Shapes and paths only, never file content.
 */
import { matchesGlob, posix } from "node:path";

import type { NormalizedToolCall } from "../core/events.ts";
import { commandName, parseShell } from "../generic/shell.ts";
import { pathLikeInputValues, WRITE_TOOLS, writtenPaths } from "../generic/sensitive-writes.ts";
import type { PolicyRule } from "./rules.ts";

/**
 * `./x`, `a/../x` and absolute paths inside the repo all become one
 * repository-relative form; a path outside the repo stays absolute.
 * ponytail: lexical only -- symlinks are not resolved (KNOWN-GAPS §1.18).
 */
export function normalizeOperand(value: string, repoRoot: string): string {
  const absolute = posix.resolve(repoRoot, value);
  const inside = posix.relative(repoRoot, absolute);
  return inside.startsWith("..") ? absolute : inside;
}

export function matchPolicyRules(
  call: NormalizedToolCall,
  rules: readonly PolicyRule[],
  repoRoot: string,
): readonly PolicyRule[] {
  if (rules.length === 0) return [];

  const raw = call.input["command"];
  const commands = typeof raw === "string" && raw.trim() !== "" ? parseShell(raw).commands : [];

  // Every path the call names: shell operands that look like paths,
  // redirection targets, and file-tool path inputs.
  const paths = new Set<string>();
  for (const command of commands) {
    for (const word of command.argv.slice(1)) {
      const text = word.text;
      if (!text.startsWith("-") && (text.includes("/") || /\.\w+$/.test(text))) {
        paths.add(normalizeOperand(text, repoRoot));
      }
    }
    for (const target of command.writes ?? []) paths.add(normalizeOperand(target, repoRoot));
  }
  for (const value of pathLikeInputValues(call.input)) paths.add(normalizeOperand(value, repoRoot));

  const under = (dir: string) => {
    const prefix = dir.endsWith("/") ? dir : `${dir}/`;
    return [...paths].some((path) => `${path}/`.startsWith(prefix));
  };

  return rules.filter(({ match }) => {
    const { command, argsContain, toolName, writePrefix, readPrefix, pathGlob } = match;
    if (command !== undefined && !commands.some((c) => c.argv[0] !== undefined && commandName(c.argv[0].text) === command)) {
      return false;
    }
    if (
      argsContain !== undefined &&
      !commands.some((c) => c.argv.slice(1).some((w) => argsContain.some((needle) => w.text.includes(needle))))
    ) {
      return false;
    }
    if (toolName !== undefined && call.toolName !== toolName) return false;
    if (
      writePrefix !== undefined &&
      !commands.some((c) => writtenPaths(c, [], [writePrefix]).length > 0) &&
      !(WRITE_TOOLS.test(call.toolName) && under(writePrefix))
    ) {
      return false;
    }
    if (readPrefix !== undefined && !under(readPrefix)) return false;
    if (pathGlob !== undefined && ![...paths].some((path) => matchesGlob(path, pathGlob))) return false;
    return true;
  });
}
