/**
 * Sensitive-data rails (M16, PLAN-LOCAL-POLICY §3): the deterministic floor
 * under everything probabilistic.
 *
 * Rail 2 — access tiers, by command shape only (never content):
 *   egress-coupled read (curl -d @.env, scp ~/.aws/… host:) -> DENY, all profiles
 *   plain read into tool output (cat .env, the read tool)        -> ASK,  all profiles
 *   metadata only (ls ~/.ssh)                                    -> untouched
 * Rail 1 — the never-send corpus: the same predicate decides what may never
 * leave the machine, for every present and future sender (M17's classifier
 * is its first consumer). Extend-only via `sensitive.neverSend` in config.
 * Rail 3 — redaction of anything that does leave.
 *
 * `ssh`/`scp -i key` name a key without exfiltrating it; flag values are not
 * operands (D10). Input redirection (`< file`) is not parsed by the shell
 * grammar and is a documented bound.
 */
import { homedir } from "node:os";
import { matchesGlob } from "node:path";

import type { SupplyChainEvent } from "../core/events.ts";
import { commandName, type SimpleCommand } from "./shell.ts";
import { GENERIC_ECOSYSTEM } from "./installers.ts";

/** Basename globs; matched case-insensitively against the final segment. */
const SENSITIVE_BASENAMES = [
  ".env*",
  "*.pem",
  "*.key",
  "*.p12",
  "*.pfx",
  "*.kdbx",
  ".netrc",
  ".npmrc",
  "id_rsa*",
  "id_ed25519*",
  "id_ecdsa*",
  "credentials",
  ".tfvars",
  ".tfstate*",
  "*secret*",
  "*credential*",
];

/** Directory names whose contents are sensitive wherever they appear. */
const SENSITIVE_DIRS = [
  ".ssh",
  ".gnupg",
  ".aws",
  ".gcloud",
  ".docker",
  ".kube",
];

/** Tools whose sensitive operand is being SENT somewhere: the exfiltration shape. */
const EGRESS_TOOLS = new Set(["curl", "wget", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "socat", "ftp"]);

/** Tools that only name a file: no content leaves the disk. */
const METADATA_TOOLS = new Set(["ls", "stat", "du", "find", "basename", "dirname", "echo", "printf", "test", "[", "true", "false"]);

/**
 * Tools that USE a key or config path passed by flag (`ssh -i key`,
 * `scp -F config`) rather than reading or sending it. Scoped per tool: the
 * same `-F` on curl is a form upload.
 */
const KEY_USERS = new Set(["ssh", "scp", "sftp", "rsync", "git", "ssh-add", "ssh-keygen", "sshfs"]);
const KEY_FLAGS = new Set(["-i", "-F", "-e", "--identity", "--identity-file", "--config"]);

/**
 * Is this operand a sensitive path? `@file` (curl body), quotes and a remote
 * `host:` prefix are tolerated; `~` expands to the real home.
 */
export function isSensitivePath(value: string, extra: readonly string[] = []): boolean {
  let path = value.trim().replace(/^@/, "").replace(/^["']|["']$/g, "");
  const colon = path.indexOf(":");
  if (colon > 0 && !path.includes("/") && !path.startsWith("/")) path = path.slice(colon + 1); // scp remote
  if (path === "" || path === "-") return false;
  if (path.startsWith("~/")) path = `${homedir()}/${path.slice(2)}`;

  const lower = path.toLowerCase();
  const basename = lower.slice(lower.lastIndexOf("/") + 1);
  const segments = lower.split("/").filter((s) => s !== "" && s !== ".");

  if (segments.some((segment) => SENSITIVE_DIRS.includes(segment))) return true;
  if (SENSITIVE_BASENAMES.some((glob) => matchesGlob(basename, glob))) return true;
  // Operator extensions match the whole path or the basename, so both
  // `keys/prod.pem` and a bare `prod.pem` are covered.
  return extra.some(
    (glob) => matchesGlob(lower, glob.toLowerCase()) || matchesGlob(basename, glob.toLowerCase()),
  );
}

/** Rail 3: strip credential-shaped text before anything leaves the machine. */
export function redactForTransport(text: string): string {
  return text
    // Bearer first: `Authorization: Bearer <tok>` must lose the token, not
    // just the word "Bearer" to the key=value rule below.
    .replace(/bearer\s+[a-z0-9._~+/=-]{8,}/gi, "bearer REDACTED")
    .replace(/(token|api[-_]?key|secret|password|passwd|pwd)(["']?\s*[:=]\s*)\S+/gi, "$1$2REDACTED")
    .replace(/\bsk-[a-z0-9-]{8,}\b/gi, "sk-REDACTED")
    .replace(/\b[a-f0-9]{40,}\b/gi, "REDACTED");
}

function event(
  decision: "ask" | "deny",
  summary: string,
  artifact: string,
): SupplyChainEvent {
  return {
    eventClass: "SensitiveAccess",
    ecosystem: GENERIC_ECOSYSTEM,
    classification: decision === "deny" ? "THIRD_PARTY_MUTATION" : "THIRD_PARTY_CAPABLE",
    artifact,
    summary,
    ...(decision === "deny" ? { minimumDecision: "deny" as const } : {}),
  };
}

/**
 * Rail 2 for shell commands: the first sensitive operand decides the tier.
 * Unknown tools with a sensitive operand get the read tier (ask) — fail
 * toward the human, not toward silence.
 */
export function sensitiveAccessFromCommands(
  commands: readonly SimpleCommand[],
  extra: readonly string[] = [],
): readonly SupplyChainEvent[] {
  const events: SupplyChainEvent[] = [];
  const seen = new Set<string>();
  for (const [index, command] of commands.entries()) {
    const head = command.argv[0] !== undefined ? commandName(command.argv[0].text) : "";
    if (head === "") continue;

    let operand: string | undefined;
    for (let i = 1; i < command.argv.length; i += 1) {
      const word = command.argv[i];
      if (word === undefined) break;
      if (word.text.startsWith("-")) {
        // A flag's value is a path USED (`ssh -i key`, `scp -i key`), not
        // content read into the agent's context or sent anywhere.
        if (KEY_USERS.has(head) && (KEY_FLAGS.has(word.text) || word.text.startsWith("--identity"))) {
          i += 1;
          continue;
        }
        // `--post-file=.env`, `-F file=@.env`: the value is joined on.
        const joined = word.text.slice(word.text.indexOf("=") + 1);
        if (word.text.includes("=") && isSensitivePath(joined.replace(/^\w+=/, ""), extra)) {
          operand = joined;
          break;
        }
        continue;
      }
      // `-F file=@.env` carries the value as its own `key=@path` word.
      const value = /^\w+=@/.test(word.text) ? word.text.slice(word.text.indexOf("=") + 1) : word.text;
      if (isSensitivePath(value, extra)) {
        operand = value;
        break;
      }
    }
    if (operand === undefined || METADATA_TOOLS.has(head)) continue;
    if (seen.has(operand)) continue;
    seen.add(operand);

    // `cat .env | base64 | curl -d @- …`: a read piped (through any stages)
    // into a network tool is the same exfiltration as naming the file to it.
    // Only this command's own pipeline counts; `;`/`&&` end it.
    let pipedToEgress = false;
    for (const next of commands.slice(index + 1)) {
      if (next.precededBy !== "|" && next.precededBy !== "|&") break;
      const tool = next.argv[0] !== undefined ? commandName(next.argv[0].text) : "";
      if (EGRESS_TOOLS.has(tool)) {
        pipedToEgress = true;
        break;
      }
    }

    events.push(
      EGRESS_TOOLS.has(head) || pipedToEgress
        ? event(
            "deny",
            `\`${head}\` ${pipedToEgress ? "pipes" : "names"} ${operand}, a sensitive path, ` +
              `${pipedToEgress ? "into" : "in"} a command that sends data to the network — ` +
              `the exfiltration shape, denied in every profile`,
            operand,
          )
        : event(
            "ask",
            `\`${head}\` reads ${operand}, a sensitive path; its content would enter the ` +
              `agent's context and the audit trail`,
            operand,
          ),
    );
  }
  return events;
}

/** Rail 2 for file tools: a sensitive path in a tool input is an access. */
export function sensitiveAccessFromPaths(
  toolName: string,
  paths: readonly string[],
  extra: readonly string[] = [],
): readonly SupplyChainEvent[] {
  const sensitive = paths.find((path) => isSensitivePath(path, extra));
  if (sensitive === undefined) return [];
  // Name-only tools are metadata; everything else (read, grep, edit, write)
  // either shows content or rewrites credentials.
  if (/^(glob|ls|stat|find)$/.test(toolName)) return [];
  return [
    event(
      "ask",
      `the ${toolName} tool names ${sensitive}, a sensitive path; its content would enter ` +
        `the agent's context and the audit trail`,
      sensitive,
    ),
  ];
}
