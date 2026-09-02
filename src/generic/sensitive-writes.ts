/**
 * Writes to tracked manifests, caught BEFORE they happen (SPEC 14, M9).
 *
 * Manifest reconciliation is retrospective by construction: the host fires
 * `tool_call` before a tool runs, so a file change can only be observed on the
 * NEXT call. That leaves one shape uncovered, and it is the one an adversary
 * would pick:
 *
 *     sed -i s/v1.2.3/v9.9.9/ go.mod && go build ./... && git checkout go.mod
 *
 * The manifest ends byte-identical, so no snapshot comparison will ever see it,
 * while the build ran against the substituted version.
 *
 * This module closes that for the shapes a command can be READ to perform: a
 * redirection into a tracked file, an in-place editor named with one, a copy or
 * move onto one. It cannot cover `python3 rewrite.py` -- nothing short of
 * filesystem watching can -- so it is a narrowing of the gap, not a closure,
 * and `docs/KNOWN-GAPS.md` says so.
 */

import type { SupplyChainEvent } from "../core/events.ts";
import { commandName, type SimpleCommand } from "./shell.ts";
import { GENERIC_ECOSYSTEM } from "./installers.ts";

/**
 * Tools that write a file named in their arguments.
 *
 * Each entry says which argument positions are destinations, because
 * `cp a b` writes `b` while `sed -i … f` writes `f` and `tee f` writes `f`.
 */
const IN_PLACE_EDITORS = new Set(["sed", "perl", "awk", "gawk", "ed"]);
const WRITES_ALL_OPERANDS = new Set(["tee", "truncate", "shred", "dd"]);
const WRITES_LAST_OPERAND = new Set(["cp", "mv", "install", "rsync", "ln"]);
/** Commands that restore a file from elsewhere, i.e. overwrite it. */
const RESTORES = new Set(["git"]);

function operands(command: SimpleCommand): string[] {
  return command.argv.slice(1).map((word) => word.text);
}

/** `sed -i`, `perl -i`, `awk -i inplace`: edits the file rather than stdout. */
function editsInPlace(command: SimpleCommand): boolean {
  return operands(command).some(
    (word) => /^-[a-zA-Z]*i/.test(word) || word === "--in-place" || word === "inplace",
  );
}

/**
 * Which tracked paths would this command write?
 *
 * Matching is by path suffix so `./go.mod` and `sub/go.mod` are recognized;
 * a repository-relative watched path is matched against the tail of the
 * argument, which is what a shell command actually carries.
 */
export function writtenPaths(
  command: SimpleCommand,
  watched: readonly string[],
): readonly string[] {
  const candidates: string[] = [...(command.writes ?? [])];
  const head = command.argv[0];
  const tool = head === undefined ? "" : commandName(head.text);
  const args = operands(command);
  const positional = args.filter((word) => !word.startsWith("-"));

  if (IN_PLACE_EDITORS.has(tool) && editsInPlace(command)) {
    // The script itself is an operand too; every remaining one is a file.
    candidates.push(...positional);
  } else if (WRITES_ALL_OPERANDS.has(tool)) {
    candidates.push(...positional, ...args.filter((word) => word.startsWith("of=")).map((w) => w.slice(3)));
  } else if (WRITES_LAST_OPERAND.has(tool)) {
    const last = positional[positional.length - 1];
    if (last !== undefined) candidates.push(last);
  } else if (RESTORES.has(tool)) {
    // `git checkout -- go.mod` and `git restore go.mod` overwrite the file
    // from the index. That is how a temporary substitution gets reverted.
    const sub = positional[0];
    if (sub === "checkout" || sub === "restore" || sub === "stash") {
      candidates.push(...positional.slice(1));
    }
  }

  const hits = new Set<string>();
  for (const candidate of candidates) {
    const normalized = candidate.replace(/^\.\//, "");
    for (const path of watched) {
      if (normalized === path || normalized.endsWith(`/${path}`) || path.endsWith(`/${normalized}`)) {
        hits.add(path);
      }
    }
  }
  return [...hits].sort();
}

/**
 * Events for a command that writes a tracked manifest with a generic tool.
 *
 * Classified as a mutation and gated: whatever the file ends up containing, the
 * decision to rewrite a dependency manifest outside the package manager is a
 * trust decision, and it is being made here rather than discovered later.
 */
export function inspectSensitiveWrites(
  commands: readonly SimpleCommand[],
  watched: readonly string[],
): readonly SupplyChainEvent[] {
  if (watched.length === 0) return [];

  const events: SupplyChainEvent[] = [];
  const reported = new Set<string>();

  for (const command of commands) {
    const head = command.argv[0];
    const tool = head === undefined ? "redirection" : commandName(head.text);

    // `go` is NOT exempt. Its own manifest-writing subcommands never name the
    // file as an operand, so they are not matched here anyway -- but
    // `go list -m all > go.sum` is a redirection into a manifest like any
    // other, and exempting the tool would have made it the one way through.
    for (const path of writtenPaths(command, watched)) {
      if (reported.has(path)) continue;
      reported.add(path);
      events.push({
        eventClass: "LockfileMutation",
        ecosystem: GENERIC_ECOSYSTEM,
        classification: "THIRD_PARTY_MUTATION",
        artifact: path,
        summary:
          `\`${tool}\` writes ${path} directly, outside the package manager. A dependency ` +
          `manifest rewritten this way never passes the command gate, and a change that is ` +
          `reverted before the next tool call would leave no trace at all.`,
      });
    }
  }

  return events;
}
