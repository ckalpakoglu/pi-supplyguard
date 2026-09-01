/**
 * The Go ecosystem adapter (SPEC 7, 10; milestone M2).
 *
 * This is the only place in the codebase that knows what `go get` means. It
 * translates command-shaped tool calls into normalized events and hands them
 * to the ecosystem-agnostic engine, which decides.
 *
 * DELEGATION NOTE (human decision, 2026-09-01)
 * --------------------------------------------
 * Dependency mutations are Chief-only. A delegated worker runs headless, a
 * THIRD_PARTY_MUTATION produces an ASK, and a headless ASK fails closed
 * (SPEC 17.1). So a worker simply cannot add or upgrade a Go dependency; the
 * Chief performs that trust decision with a human present. This needs no code
 * here -- it is what the engine already does -- but it is load-bearing
 * behavior, so `test/go/adapter.test.ts` pins it. Brokered or pre-scoped
 * worker approval is deferred to M4.
 *
 * SCOPE: M2 is the command gate only. Detecting indirect mutation of go.mod
 * through `sed`, Python or a generated script is M3's manifest-snapshot work
 * (SPEC 14); intercepting commands is explicitly not sufficient on its own.
 */

import type {
  AdapterContext,
  AdapterToolCallResult,
  EcosystemAdapter,
} from "../registry.ts";
import type { NormalizedToolCall, SupplyChainEvent } from "../../core/events.ts";
import { analyzeCommand, GO_ECOSYSTEM, type GoOperation } from "./commands.ts";

/**
 * Pull the shell command out of a tool call.
 *
 * Keyed on the shape of the input rather than on a hard-coded tool name: Pi's
 * bash tool passes `command`, and keying on the field means a renamed or
 * additional command-shaped tool is still inspected. A tool call without one
 * is not a command and is not this adapter's business.
 */
function shellCommand(call: NormalizedToolCall): string | undefined {
  const command = call.input["command"];
  return typeof command === "string" && command.trim() !== "" ? command : undefined;
}

function toEvent(operation: GoOperation): SupplyChainEvent {
  return {
    eventClass: operation.eventClass,
    ecosystem: GO_ECOSYSTEM,
    classification: operation.classification,
    summary: operation.summary,
    ...(operation.artifact === undefined ? {} : { artifact: operation.artifact }),
    ...(operation.version === undefined ? {} : { version: operation.version }),
    ...(operation.minimumDecision === undefined
      ? {}
      : { minimumDecision: operation.minimumDecision }),
  };
}

export function createGoAdapter(): EcosystemAdapter {
  return {
    id: GO_ECOSYSTEM,

    inspectToolCall(call: NormalizedToolCall, _ctx: AdapterContext): AdapterToolCallResult {
      const command = shellCommand(call);
      if (command === undefined) {
        return { classification: "SUPPLY_CHAIN_IRRELEVANT", events: [] };
      }

      const analysis = analyzeCommand(command);
      const events = analysis.operations.map(toEvent);

      // An unreadable command is unknown risk, not absence of risk. The
      // classification alone carries that: the engine's UNKNOWN_RISK baseline
      // is ask / ask / deny, which is SPEC 5.1's "fail conservative according
      // to the active profile". Do NOT synthesize an event for it -- event
      // classes such as SecurityBypass deny in every profile and would flatten
      // that gradation.
      //
      // ponytail: the specific reason (`analysis.notes`) does not reach the
      // audit record, because the adapter contract has no notes channel. Add
      // one in M3, when `inspectFileMutation` widens the contract anyway.
      return { classification: analysis.classification, events };
    },
  };
}
