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
import type { FileMutation } from "../core/manifest.ts";
import type { Profile } from "../core/profiles.ts";

export interface AdapterContext {
  readonly repoRoot: string;
  readonly profile: Profile;
}

/**
 * Context for the project-scoped hooks.
 *
 * `decisions` holds the answers to this adapter's project-level questions
 * (SPEC 9.2, 13.3), keyed by request id -- opaque strings to the core. A
 * missing key means the question has not been answered, and an adapter must
 * then fall back to its own conservative default rather than assume consent.
 */
export interface ProjectDecisionContext extends AdapterContext {
  readonly decisions: Readonly<Record<string, string>>;
}

export interface AdapterToolCallResult {
  readonly classification: ToolCallClassification;
  readonly events: readonly SupplyChainEvent[];
  /**
   * True when this call is EXPECTED to rewrite files the adapter tracks.
   *
   * Manifest reconciliation (SPEC 14.2) compares snapshots across tool calls,
   * so it needs to know which changes were produced by an operation that
   * already passed the gate. Without this, an approved `go get` would be
   * re-gated on the next tool call for the go.mod line it just wrote.
   */
  readonly expectsManifestChange?: boolean;
  /**
   * Non-secret explanations that are evidence, not decisions -- why a command
   * could not be read, why a recommendation was not enforced. They reach the
   * audit record; they never change a decision.
   */
  readonly notes?: readonly string[];
}

/** Events derived from the repository's current state (SPEC 7, 9.4). */
export interface AdapterProjectStateResult {
  readonly events: readonly SupplyChainEvent[];
  readonly notes?: readonly string[];
}

/**
 * A question SupplyGuard asks a human ONCE per project (SPEC 9.2, 13.3).
 *
 * The core neither knows nor interprets `id` and the option strings; it
 * prompts, persists and audits. Vendor mode is the first user; the Hardened
 * Socket Firewall opt-in (M7) is the second.
 */
export interface ProjectDecisionOption {
  /** What the human sees. */
  readonly label: string;
  /** What is persisted and what the adapter compares against. */
  readonly value: string;
}

export interface ProjectDecisionRequest {
  /** Stable key, e.g. `"go.vendorMode"`. Namespaced by ecosystem/provider. */
  readonly id: string;
  readonly question: string;
  readonly options: readonly ProjectDecisionOption[];
  /** Value presented first, i.e. the recommended interactive answer. */
  readonly recommended: string;
  /**
   * Used when no human is reachable. MUST be the conservative choice: a
   * headless session is not consent (SPEC 17.1).
   */
  readonly headlessValue: string;
  /** Non-secret audit note recorded when the headless value is used. */
  readonly headlessNote: string;
}

/**
 * The adapter contract.
 *
 * M1 declared only `inspectToolCall`. M3 adds the SPEC 7 hooks it actually
 * wires: the sensitive-path set and `inspectFileMutation` for manifest
 * reconciliation (SPEC 14), `inspectProjectState` for vendor state (SPEC 9.4),
 * and `projectDecisions` for ask-once project questions (SPEC 9.2). `verify`
 * still does not exist, because nothing calls it yet -- declaring a hook
 * before anything invokes it advertises enforcement that is not there.
 *
 * Every hook beyond `inspectToolCall` is optional: an adapter that only
 * understands commands remains valid.
 */
export interface EcosystemAdapter {
  /** Stable ecosystem id, e.g. `"go"`. Opaque to the core. */
  readonly id: string;

  /** Classify a tool call and emit normalized events. Must not execute it. */
  inspectToolCall(
    call: NormalizedToolCall,
    ctx: AdapterContext,
  ): Promise<AdapterToolCallResult> | AdapterToolCallResult;

  /**
   * Repository-relative paths whose content this adapter can classify.
   *
   * Constant per adapter: the core snapshots these before every tool call, so
   * the set may not depend on repository state that a tool call could change.
   */
  sensitivePaths?(): readonly string[];

  /** Classify an observed before/after change to one sensitive file. */
  inspectFileMutation?(
    mutation: FileMutation,
    ctx: AdapterContext,
  ): Promise<readonly SupplyChainEvent[]> | readonly SupplyChainEvent[];

  /** Events implied by the repository's current state, e.g. vendor drift. */
  inspectProjectState?(
    ctx: ProjectStateContext,
  ): Promise<AdapterProjectStateResult> | AdapterProjectStateResult;

  /** Project-level questions that still need a human answer. */
  projectDecisions?(
    ctx: ProjectDecisionContext,
  ): Promise<readonly ProjectDecisionRequest[]> | readonly ProjectDecisionRequest[];

  /** Non-secret status lines for `/supplyguard-status` (SPEC 19.2). */
  describe?(ctx: ProjectDecisionContext): Promise<readonly string[]> | readonly string[];
}

/**
 * Project-state inspection sees how the current call was classified.
 *
 * SPEC 9.3 gates on it: Paranoid denies a DEPENDENCY-CHANGING operation when
 * no vendor tree exists, rather than denying every command in the repository.
 */
export interface ProjectStateContext extends ProjectDecisionContext {
  readonly classification: ToolCallClassification;
  /**
   * Events already produced for this call, by the command gate and by manifest
   * reconciliation.
   *
   * An adapter needs them to avoid gating the operation that FIXES the state it
   * is reporting: denying `go mod vendor` because the vendor tree is stale
   * leaves no way out but editing configuration, which SPEC 17.2 says is not
   * the override mechanism.
   */
  readonly events: readonly SupplyChainEvent[];
}

export interface AdapterError {
  readonly adapterId: string;
  readonly message: string;
}

export interface RegistryInspection {
  readonly classification: ToolCallClassification;
  readonly events: readonly SupplyChainEvent[];
  readonly errors: readonly AdapterError[];
  readonly notes: readonly string[];
  /** True when ANY adapter expects this call to rewrite tracked files. */
  readonly expectsManifestChange: boolean;
}

export interface RegistryStateInspection {
  readonly events: readonly SupplyChainEvent[];
  readonly errors: readonly AdapterError[];
  readonly notes: readonly string[];
}

export interface AdapterRegistry {
  register(adapter: EcosystemAdapter): void;
  list(): readonly EcosystemAdapter[];
  size(): number;
  inspectToolCall(
    call: NormalizedToolCall,
    ctx: AdapterContext,
  ): Promise<RegistryInspection>;
  /** Union of every adapter's sensitive paths, de-duplicated and sorted. */
  sensitivePaths(): readonly string[];
  /** Classify observed file mutations through every adapter. */
  inspectFileMutations(
    mutations: readonly FileMutation[],
    ctx: AdapterContext,
  ): Promise<RegistryStateInspection>;
  inspectProjectState(ctx: ProjectStateContext): Promise<RegistryStateInspection>;
  projectDecisions(ctx: ProjectDecisionContext): Promise<readonly ProjectDecisionRequest[]>;
  /** Status lines from every adapter. Never throws: status must always render. */
  describe(ctx: ProjectDecisionContext): Promise<readonly string[]>;
}

/**
 * Run one inspection across every adapter, isolating failures.
 *
 * SECURITY: a failed adapter must not silently become "nothing to see here".
 * The error is reported so the engine can treat the call as unknown risk.
 */
async function collect(
  adapters: Iterable<EcosystemAdapter>,
  run: (adapter: EcosystemAdapter) => Promise<AdapterProjectStateResult>,
): Promise<RegistryStateInspection> {
  const events: SupplyChainEvent[] = [];
  const errors: AdapterError[] = [];
  const notes: string[] = [];

  for (const adapter of adapters) {
    try {
      const result = await run(adapter);
      events.push(...result.events);
      notes.push(...(result.notes ?? []));
    } catch (error) {
      errors.push({
        adapterId: adapter.id,
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return { events, errors, notes };
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
      const notes: string[] = [];
      const classifications: ToolCallClassification[] = [];
      let expectsManifestChange = false;

      for (const adapter of registered.values()) {
        try {
          const result = await adapter.inspectToolCall(call, ctx);
          classifications.push(result.classification);
          events.push(...result.events);
          notes.push(...(result.notes ?? []));
          expectsManifestChange ||= result.expectsManifestChange === true;
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
        notes,
        expectsManifestChange,
      };
    },

    sensitivePaths() {
      const paths = new Set<string>();
      for (const adapter of registered.values()) {
        for (const path of adapter.sensitivePaths?.() ?? []) paths.add(path);
      }
      return [...paths].sort();
    },

    async inspectFileMutations(mutations, ctx) {
      return collect(registered.values(), async (adapter) => {
        if (adapter.inspectFileMutation === undefined || mutations.length === 0) {
          return { events: [] };
        }
        const events: SupplyChainEvent[] = [];
        for (const mutation of mutations) {
          events.push(...(await adapter.inspectFileMutation(mutation, ctx)));
        }
        return { events };
      });
    },

    async inspectProjectState(ctx) {
      return collect(registered.values(), async (adapter) =>
        adapter.inspectProjectState === undefined
          ? { events: [] }
          : adapter.inspectProjectState(ctx),
      );
    },

    async describe(ctx) {
      const lines: string[] = [];
      for (const adapter of registered.values()) {
        try {
          lines.push(...((await adapter.describe?.(ctx)) ?? []));
        } catch (error) {
          lines.push(
            `${adapter.id}: state unavailable (${
              error instanceof Error ? error.message : String(error)
            })`,
          );
        }
      }
      return lines;
    },

    async projectDecisions(ctx) {
      const requests: ProjectDecisionRequest[] = [];
      for (const adapter of registered.values()) {
        // SECURITY: an adapter that cannot state its questions must not
        // silently skip them -- an unasked question would read as "answered".
        // The throw propagates to the engine, which fails closed.
        requests.push(...(await (adapter.projectDecisions?.(ctx) ?? [])));
      }
      return requests;
    },
  };

  for (const adapter of adapters) registry.register(adapter);
  return registry;
}
