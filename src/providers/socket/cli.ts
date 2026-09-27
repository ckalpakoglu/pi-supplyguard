/**
 * Running the Socket CLI (SPEC 13, 20).
 *
 * This is the only place SupplyGuard starts a process, and the rules that
 * follow from that are not negotiable:
 *
 * - `execFile`, never a shell. Arguments are an array, so no quoting question
 *   can ever arise from a module path.
 * - Arguments are validated before they are passed. A purl that could be read
 *   as a flag is refused rather than escaped. The only flags that pass are
 *   SupplyGuard's own constants (`CLI_FLAGS`), matched exactly.
 * - The environment is an allow-list. A security tool that spawns a process
 *   with the agent's full environment has handed it every secret in the
 *   session.
 * - A timeout, an output cap, and no throw: every failure is a result the
 *   profile can weigh.
 */

import { execFile } from "node:child_process";

/** Socket scans are slower than an HTTP call; they still may not hang a gate. */
export const SOCKET_TIMEOUT_MS = 30_000;

/** Largest accepted stdout. A score report is a few kilobytes. */
const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;

/**
 * Environment variables the CLI is allowed to see.
 *
 * `SOCKET_CLI_*` carries the operator's own Socket configuration, including an
 * API token: it is forwarded because the CLI needs it, and it is never read,
 * logged or copied anywhere else by SupplyGuard.
 */
const ENV_ALLOW_LIST = ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SOCKET_CLI_"] as const;

export interface SocketRunResult {
  readonly ok: boolean;
  readonly stdout: string;
  /** Non-secret failure description. Never the raw environment. */
  readonly reason?: string;
}

export type SocketRunner = (args: readonly string[]) => Promise<SocketRunResult>;

/**
 * The flags SupplyGuard itself passes. They are compared exactly, so an
 * operand that merely starts with `-` is still refused by `isSafeArgument`.
 */
const CLI_FLAGS: Record<string, true> = { "--version": true, "--json": true };

export interface SocketCliOptions {
  /** Executable to run. Defaults to `socket` from PATH. */
  readonly command?: string;
  readonly timeoutMs?: number;
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** Injected by tests. Nothing in the suite starts a process. */
  readonly run?: SocketRunner;
}

/**
 * Is this safe to hand to a process as a positional argument?
 *
 * A leading `-` would be read as a flag, and a module path never legitimately
 * contains whitespace or shell metacharacters. Refusing is right: a path this
 * strange is not one whose Socket score would be trustworthy anyway.
 */
export function isSafeArgument(value: string): boolean {
  return value !== "" && !value.startsWith("-") && /^[A-Za-z0-9@._/:+~-]+$/.test(value);
}

function filteredEnv(
  env: Readonly<Record<string, string | undefined>>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) continue;
    if (ENV_ALLOW_LIST.some((allowed) => key === allowed || key.startsWith(allowed))) {
      out[key] = value;
    }
  }
  return out;
}

/** Build a runner that actually starts the Socket CLI. */
export function createSocketRunner(options: SocketCliOptions = {}): SocketRunner {
  if (options.run !== undefined) return options.run;

  const command = options.command ?? "socket";
  const timeout = options.timeoutMs ?? SOCKET_TIMEOUT_MS;
  const env = filteredEnv(options.env ?? process.env);

  return async (args) =>
    new Promise<SocketRunResult>((resolve) => {
      if (!args.every((arg) => CLI_FLAGS[arg] === true || isSafeArgument(arg))) {
        resolve({ ok: false, stdout: "", reason: "refused to pass an unsafe argument" });
        return;
      }

      execFile(
        command,
        [...args],
        { timeout, maxBuffer: MAX_OUTPUT_BYTES, env, windowsHide: true },
        (error, stdout) => {
          if (error === null) {
            resolve({ ok: true, stdout });
            return;
          }
          // A non-zero exit is normal for this CLI: `--json` still prints a
          // result document, so stdout is kept and the caller decides.
          const code = (error as NodeJS.ErrnoException).code;
          resolve({
            ok: false,
            stdout,
            reason:
              code === "ENOENT"
                ? "the socket CLI is not installed or not on PATH"
                : code === "ETIMEDOUT"
                  ? "the socket CLI did not finish in time"
                  : `the socket CLI exited with an error (${code ?? "non-zero status"})`,
          });
        },
      );
    });
}
