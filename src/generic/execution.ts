/**
 * Execution-classifier targeting (M17): which calls leave the machine, and
 * what of them.
 *
 * Deterministic, local, decided BEFORE any provider is consulted (the
 * classifier never decides whether its own guardrails apply):
 * - only shell commands are candidates (file tools are covered by rails);
 * - a command made only of read-only tools never leaves the machine
 *   (invariant 9: `ls` and `git status` are not sent anywhere);
 * - the command text is redacted (rail 3);
 * - the one local script it executes is read for stage 2 -- unless rail 1
 *   says the path is sensitive, in which case nothing of it is sent.
 */
import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";

import { isSensitivePath, redactForTransport } from "./sensitive-access.ts";
import { commandName, parseShell, type SimpleCommand } from "./shell.ts";

/** Tools that cannot change the world. A command made only of these is never sent. */
const READ_ONLY = new Set([
  "ls", "pwd", "cat", "head", "tail", "less", "more", "wc", "grep", "rg", "find", "fd",
  "echo", "printf", "true", "false", "test", "[", "which", "type", "file", "stat", "du",
  "df", "date", "whoami", "id", "uname", "env", "printenv", "sort", "uniq", "cut", "tr",
  "diff", "cmp", "tree", "realpath", "dirname", "basename", "jq", "gofmt",
]);

/** `git` subcommands that only read. */
const GIT_READ_ONLY = new Set(["status", "log", "diff", "show", "branch", "rev-parse", "remote", "blame", "ls-files", "describe"]);

/** Interpreters whose first operand is a script file to execute. */
const INTERPRETERS = new Set(["sh", "bash", "zsh", "dash", "python", "python3", "node", "bun", "deno", "ruby", "perl", "php"]);

const FILE_BYTE_BUDGET = 256 * 1024;

function isReadOnly(command: SimpleCommand): boolean {
  const head = command.argv[0];
  if (head === undefined) return command.writes === undefined || command.writes.length === 0;
  const tool = commandName(head.text);
  if ((command.writes ?? []).length > 0) return false; // `echo x > f` writes
  if (tool === "git") return GIT_READ_ONLY.has(command.argv[1]?.text ?? "");
  if (tool === "find") return !command.argv.some((w) => w.text === "-delete" || w.text === "-exec");
  return READ_ONLY.has(tool);
}

export interface ExecutionCandidate {
  readonly command: string;
  readonly file?: { readonly path: string; readonly text: string };
  /** Present when a script was executed but rail 1 refused to send it. */
  readonly refused?: string;
}

/**
 * The classifier input for a call, or `undefined` when nothing should leave
 * the machine.
 */
export async function executionCandidate(
  input: Readonly<Record<string, unknown>>,
  repoRoot: string,
  sensitiveGlobs: readonly string[] = [],
): Promise<ExecutionCandidate | undefined> {
  const raw = input["command"];
  if (typeof raw !== "string" || raw.trim() === "") return undefined;
  const parsed = parseShell(raw);
  if (!parsed.opaque && parsed.commands.every(isReadOnly)) return undefined;

  const command = redactForTransport(raw);

  // Stage 2 target: the first `interpreter script` or `./script`.
  for (const simple of parsed.commands) {
    const head = simple.argv[0]?.text;
    if (head === undefined) continue;
    const tool = commandName(head);
    const script = INTERPRETERS.has(tool)
      ? simple.argv.slice(1).find((w) => !w.text.startsWith("-"))?.text
      : head.startsWith("./") || head.startsWith("/")
        ? head
        : undefined;
    if (script === undefined) continue;

    if (isSensitivePath(script, sensitiveGlobs)) return { command, refused: script };
    try {
      const path = resolve(repoRoot, script);
      const info = await stat(path);
      if (!info.isFile() || info.size > FILE_BYTE_BUDGET) return { command };
      const text = await readFile(path, "utf8");
      // Binary content is not a script to read.
      if (text.includes("\u0000")) return { command };
      return { command, file: { path: script, text: redactForTransport(text) } };
    } catch {
      return { command };
    }
  }
  return { command };
}
