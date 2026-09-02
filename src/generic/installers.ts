/**
 * Installer pipelines and network fetches (SPEC 15.2, 4.4).
 *
 * `curl … | sh` hands the shell whatever a server chose to send, with no
 * artifact to review, no version to pin and no checksum to verify. SPEC 15.2
 * denies it in every profile, and this is one of the few rules that does not
 * vary with the security profile at all.
 *
 * The distinction that matters is the PIPE. `curl -o install.sh …` writes a
 * file that can be read before it runs, and SPEC 15.2 says so explicitly: a
 * download without immediate execution is a different event, evaluated under
 * network policy rather than denied outright.
 */

import type { SupplyChainEvent } from "../core/events.ts";
import { commandName, type SimpleCommand } from "./shell.ts";

export const GENERIC_ECOSYSTEM = "generic";

/** Commands that fetch a URL and write it to stdout or a file. */
const DOWNLOADERS = new Set(["curl", "wget", "fetch", "aria2c", "httpie", "http"]);

/** Interpreters that will execute a script arriving on stdin. */
const INTERPRETERS = new Set([
  "sh",
  "bash",
  "zsh",
  "dash",
  "ksh",
  "ash",
  "fish",
  "python",
  "python2",
  "python3",
  "perl",
  "ruby",
  "node",
  "php",
]);

function isDownloader(command: SimpleCommand): boolean {
  const head = command.argv[0];
  return head !== undefined && DOWNLOADERS.has(commandName(head.text));
}

/**
 * Is this interpreter about to run whatever arrives on stdin?
 *
 * `sh` with no operand reads stdin. `sh -s`, `bash -` and `python -` say so
 * explicitly. `sh install.sh` names a file instead, and is not this event.
 */
function readsStdinScript(command: SimpleCommand): boolean {
  const head = command.argv[0];
  if (head === undefined || !INTERPRETERS.has(commandName(head.text))) return false;

  for (const word of command.argv.slice(1)) {
    if (word.text === "-" || word.text === "-s") continue;
    // `-c 'script'` runs its argument, not stdin; other flags are ignored, and
    // any non-flag operand is a script FILE.
    if (!word.text.startsWith("-")) return false;
    if (/^-[a-z]*c[a-z]*$/.test(word.text)) return false;
  }
  return true;
}

/**
 * Detect download-and-execute pipelines and plain network fetches.
 *
 * Returns events, never decisions: the pipeline event carries a `deny` floor
 * because SPEC 15.2 makes it an invariant, while a plain fetch is a
 * `NetworkRequirement` whose profile baseline is allow / ask / deny.
 */
export function inspectInstallers(
  commands: readonly SimpleCommand[],
): readonly SupplyChainEvent[] {
  const events: SupplyChainEvent[] = [];
  let sawDownloader = false;

  for (const command of commands) {
    if (command.precededBy === "|" || command.precededBy === "|&") {
      if (sawDownloader && readsStdinScript(command)) {
        const interpreter = commandName(command.argv[0]?.text ?? "");
        events.push({
          eventClass: "ThirdPartyExecution",
          ecosystem: GENERIC_ECOSYSTEM,
          classification: "THIRD_PARTY_MUTATION",
          summary:
            `a download is piped straight into \`${interpreter}\`, executing whatever the ` +
            `server returns: nothing is pinned, reviewable or checksum-verified`,
          minimumDecision: "deny",
        });
      }
    }

    if (isDownloader(command)) {
      sawDownloader = true;
      continue;
    }
    // A downloader only feeds the command immediately after it.
    sawDownloader = false;
  }

  return events;
}

/**
 * A network fetch that is NOT piped into an interpreter (SPEC 4.4, 15.2).
 *
 * Allowed and audited in standard, a gate in hardened, denied by default in
 * paranoid -- the "Build network" row of the profile matrix.
 */
export function inspectNetworkFetches(
  commands: readonly SimpleCommand[],
  pipelineEvents: number,
): readonly SupplyChainEvent[] {
  if (pipelineEvents > 0) return [];

  const events: SupplyChainEvent[] = [];
  for (const command of commands) {
    if (!isDownloader(command)) continue;
    const tool = commandName(command.argv[0]?.text ?? "");
    events.push({
      eventClass: "NetworkRequirement",
      ecosystem: GENERIC_ECOSYSTEM,
      classification: "THIRD_PARTY_CAPABLE",
      summary: `\`${tool}\` fetches from the network; the artifact is not executed directly`,
    });
  }
  return events;
}
