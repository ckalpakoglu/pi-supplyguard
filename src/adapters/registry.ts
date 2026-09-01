/**
 * Ecosystem adapter registry (SPEC 7).
 *
 * Adapters are the ONLY component allowed to understand a package manager.
 * They translate tool calls, file mutations and project state into the
 * normalized event model; the policy engine then decides. Adding npm, Python
 * or Cargo means adding an adapter, not editing the engine (SPEC 26.3).
 *
 * M1 registers NO adapters. That is deliberate: with no producers there are no
 * supply-chain events, so ordinary development is unaffected. The Go adapter
 * arrives in M2.
 */

import type {
  NormalizedToolCall,
  SupplyChainEvent,
  ToolCallClassification,
} from "../core/events.ts";
import { mostSevereClassification } from "../core/events.ts";
import type { Profile } from "../core/profiles.ts";

export interface AdapterContext {
  readonly repoRoot: string;
  readonly profile: Profile;
}

export interface AdapterToolCallResult {
  readonly classification: ToolCallClassification;
  readonly events: readonly SupplyChainEvent[];
}

/**
 * The adapter contract.
 *
 * Only `inspectToolCall` exists in M1 because it is the only hook the M1 engine
 * calls. The remaining SPEC 7 hooks -- `detectProject`, `inspectFileMutation`,
 * `inspectProjectState`, `verify` -- are added by the milestone that wires them
 * (M3 manifest reconciliation and vendor state, M3/M9 verification). Declaring
 * them before anything calls them would advertise enforcement that does not
 * exist.
 */
export interface EcosystemAdapter {
  /** Stable ecosystem id, e.g. `"go"`. Opaque to the core. */
  readonly id: string;

  /** Classify a tool call and emit normalized events. Must not execute it. */
  inspectToolCall(
    call: NormalizedToolCall,
    ctx: AdapterContext,
  ): Promise<AdapterToolCallResult> | AdapterToolCallResult;
}

export interface AdapterError {
  readonly adapterId: string;
  readonly message: string;
}

export interface RegistryInspection {
  readonly classification: ToolCallClassification;
  readonly events: readonly SupplyChainEvent[];
  readonly errors: readonly AdapterError[];
}

export interface AdapterRegistry {
  register(adapter: EcosystemAdapter): void;
  list(): readonly EcosystemAdapter[];
  size(): number;
  inspectToolCall(
    call: NormalizedToolCall,
    ctx: AdapterContext,
  ): Promise<RegistryInspection>;
}

export function createAdapterRegistry(
  adapters: readonly EcosystemAdapter[] = [],
): AdapterRegistry {
  const registered = new Map<string, EcosystemAdapter>();

  const registry: AdapterRegistry = {
    register(adapter) {
      if (registered.has(adapter.id)) {
        throw new Error(`supplyguard: duplicate ecosystem adapter id "${adapter.id}"`);
      }
      registered.set(adapter.id, adapter);
    },

    list() {
      return [...registered.values()];
    },

    size() {
      return registered.size;
    },

    async inspectToolCall(call, ctx) {
      const events: SupplyChainEvent[] = [];
      const errors: AdapterError[] = [];
      const classifications: ToolCallClassification[] = [];

      for (const adapter of registered.values()) {
        try {
          const result = await adapter.inspectToolCall(call, ctx);
          classifications.push(result.classification);
          events.push(...result.events);
        } catch (error) {
          // SECURITY: a failed adapter must not silently become "nothing to
          // see here". An adapter that cannot inspect a call leaves the call
          // unclassified, which the engine treats conservatively.
          errors.push({
            adapterId: adapter.id,
            message: error instanceof Error ? error.message : String(error),
          });
          classifications.push("UNKNOWN_RISK");
        }
      }

      return {
        classification: mostSevereClassification(...classifications),
        events,
        errors,
      };
    },
  };

  for (const adapter of adapters) registry.register(adapter);
  return registry;
}
