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
 *
 * `prefixes` are directory guards (e.g. `vendor/`): a write to any path under
 * one is reported against the prefix itself. Vendored source is not snapshotted
 * (§1.8 records why hashing a vendor tree per call is a bad trade), so the
 * command shape is the only place it can be caught.
 */
export function writtenPaths(
  command: SimpleCommand,
  watched: readonly string[],
  prefixes: readonly string[] = [],
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
    for (const prefix of prefixes) {
      if (normalized.startsWith(prefix) || normalized.includes(`/${prefix}`)) {
        hits.add(prefix);
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
 *
 * A write under a guard prefix is a VendorDrift by construction: the tree can
 * no longer be assumed to match the versions go.mod pins, and nothing will
 * reconcile it later because vendored source is not snapshotted.
 */
export function inspectSensitiveWrites(
  commands: readonly SimpleCommand[],
  watched: readonly string[],
  prefixes: readonly string[] = [],
): readonly SupplyChainEvent[] {
  if (watched.length === 0 && prefixes.length === 0) return [];

  const events: SupplyChainEvent[] = [];
  const reported = new Set<string>();

  for (const command of commands) {
    const head = command.argv[0];
    const tool = head === undefined ? "redirection" : commandName(head.text);

    // `go` is NOT exempt. Its own manifest-writing subcommands never name the
    // file as an operand, so they are not matched here anyway -- but
    // `go list -m all > go.sum` is a redirection into a manifest like any
    // other, and exempting the tool would have made it the one way through.
    for (const path of writtenPaths(command, watched, prefixes)) {
      if (reported.has(path)) continue;
      reported.add(path);
      const vendor = prefixes.includes(path);
      events.push(
        vendor
          ? {
              eventClass: "VendorDrift",
              ecosystem: GENERIC_ECOSYSTEM,
              classification: "THIRD_PARTY_MUTATION",
              artifact: path,
              summary:
                `\`${tool}\` writes vendored source under ${path} directly. The vendor ` +
                `tree is what enforced builds compile from, and a hand-edited file in ` +
                `it no longer matches the version go.mod pins -- with no checksum or ` +
                `snapshot to catch it later.`,
            }
          : {
              eventClass: "LockfileMutation",
              ecosystem: GENERIC_ECOSYSTEM,
              classification: "THIRD_PARTY_MUTATION",
              artifact: path,
              summary:
                `\`${tool}\` writes ${path} directly, outside the package manager. A dependency ` +
                `manifest rewritten this way never passes the command gate, and a change that is ` +
                `reverted before the next tool call would leave no trace at all.`,
            },
      );
    }
  }

  return events;
}

/** Tool names that write the file their arguments name. Reads are never taxed. */
const WRITE_TOOLS = /edit|write|patch|save|create|apply|notebook/i;

/**
 * A string that is nothing but a filesystem path: one token, no prose. Code
 * content that merely mentions `vendor/` inside a require() carries quotes or
 * parentheses and is excluded by construction.
 */
const PATH_LIKE = /^[A-Za-z0-9_@.~/+-]{1,512}$/;

/**
 * Writes to guarded trees through FILE tools, caught before they happen.
 *
 * The shell-side rules above read a command's operands; an `edit`/`write`
 * tool call names its target in an input field instead, and nothing else was
 * looking there. `node_modules/` and `vendor/` are not snapshotted, so the
 * pre-execution shape is the only chance to see the write at all.
 *
 * Matching mirrors `writtenPaths`: suffix match against watched paths,
 * prefix/contains against directory guards, `./` tolerated.
 */
export function inspectNonShellWrite(
  toolName: string,
  input: Readonly<Record<string, unknown>>,
  watched: readonly string[],
  prefixes: readonly string[],
): readonly SupplyChainEvent[] {
  if (watched.length === 0 && prefixes.length === 0) return [];
  if (!WRITE_TOOLS.test(toolName)) return [];

  const hits = new Map<string, "watched" | "prefix">();
  for (const value of Object.values(input)) {
    if (typeof value !== "string" || !PATH_LIKE.test(value)) continue;
    const normalized = value.replace(/^\.\//, "");
    for (const path of watched) {
      if (normalized === path || normalized.endsWith(`/${path}`) || path.endsWith(`/${normalized}`)) {
        hits.set(path, "watched");
      }
    }
    for (const prefix of prefixes) {
      if (normalized.startsWith(prefix) || normalized.includes(`/${prefix}`)) {
        hits.set(prefix, "prefix");
      }
    }
  }
  if (hits.size === 0) return [];

  const events: SupplyChainEvent[] = [];
  for (const [hit, kind] of hits) {
    events.push(
      kind === "prefix"
        ? {
            eventClass: "VendorDrift",
            ecosystem: GENERIC_ECOSYSTEM,
            classification: "THIRD_PARTY_MUTATION",
            artifact: hit,
            summary:
              `the ${toolName} tool writes vendored source under ${hit} directly. The ` +
              `tree is what enforced builds run from, a hand-edited file in it no ` +
              `longer matches the versions the manifest pins -- and with no checksum ` +
              `or snapshot, nothing catches it later.`,
          }
        : {
            eventClass: "LockfileMutation",
            ecosystem: GENERIC_ECOSYSTEM,
            classification: "THIRD_PARTY_MUTATION",
            artifact: hit,
            summary:
              `the ${toolName} tool writes ${hit} directly, outside the package ` +
              `manager. A dependency manifest rewritten this way never passes the ` +
              `command gate.`,
          },
    );
  }
  return events;
}
