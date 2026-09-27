/**
 * Host tool shapes, normalized for the core.
 *
 * Adapters read one field: `input.command`, a shell string. Pi's bash tool has
 * nothing else, but omp's tool surface can change what a command does without
 * changing that string:
 *
 * - `bash` takes `env` (named-service mode) and `cwd` on any call, so
 *   `{ command: "go build ./...", env: { GOSUMDB: "off" } }` disables checksum
 *   verification with a clean-looking command;
 * - `write` to `proc://<id>` sends its `content` to a running process's stdin,
 *   so a shell service runs whatever is written to it.
 *
 * Both are rewritten here into the shell string they are equivalent to, so the
 * existing parser and every adapter inspect them unchanged. The synthesized
 * string only ever feeds adapters; it is never shown, audited or returned to
 * the host, which keeps env values out of prompts and logs.
 */

import type { ToolCallEvent } from "@earendil-works/pi-coding-agent";

import type { NormalizedToolCall } from "../core/events.ts";

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** omp accepts a copied `[path#TAG]` snapshot reference as a path. */
const SNAPSHOT_TAG = /#[0-9A-Fa-f]{4}$/;

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

/** Text written to a process's stdin through `write proc://…`. */
function procStdin(input: Record<string, unknown>): string | undefined {
  const rawPath = input["path"];
  if (typeof rawPath !== "string") return undefined;
  let path = rawPath.trim();
  if (path.startsWith("[") && path.endsWith("]")) {
    path = path.slice(1, -1).replace(SNAPSHOT_TAG, "");
  }
  if (!path.toLowerCase().startsWith("proc://")) return undefined;
  const content = input["content"];
  return typeof content === "string" && content.trim() !== "" ? content : undefined;
}

/** `command` with the call's `env` and `cwd` spelled out in front of it. */
function commandWithContext(input: Record<string, unknown>): string | undefined {
  const command = input["command"];
  if (typeof command !== "string") return undefined;

  const prefix: string[] = [];
  const env = input["env"];
  if (typeof env === "object" && env !== null && !Array.isArray(env)) {
    for (const [key, value] of Object.entries(env)) {
      // omp validates arguments against the tool schema before the hook runs,
      // and a name that fails this test cannot be a Go variable anyway.
      if (ENV_NAME.test(key) && typeof value === "string") {
        prefix.push(`${key}=${shellQuote(value)}`);
      }
    }
  }
  const cwd = input["cwd"];
  if (typeof cwd === "string" && cwd.trim() !== "") {
    prefix.push(`cd ${shellQuote(cwd)}`);
  }

  // A newline is a command separator, and a bare `NAME=value` segment is
  // already analyzed as a checksum-bypass candidate.
  return prefix.length === 0 ? undefined : [...prefix, command].join("\n");
}

export function normalizeToolCall(event: ToolCallEvent): NormalizedToolCall {
  const raw: unknown = event.input;
  const input =
    typeof raw === "object" && raw !== null && !Array.isArray(raw)
      ? (raw as Record<string, unknown>)
      : {};
  // A file write is never analyzed as a command; only process stdin is.
  const equivalent =
    event.toolName === "write" ? procStdin(input) : commandWithContext(input);
  return {
    toolName: event.toolName,
    input: equivalent === undefined ? input : { ...input, command: equivalent },
    ...(event.toolCallId === undefined ? {} : { toolCallId: event.toolCallId }),
  };
}
