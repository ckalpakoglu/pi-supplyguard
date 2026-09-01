/**
 * Minimal hand-written ambient declaration for the Pi extension host API.
 *
 * Why this file exists
 * --------------------
 * `@earendil-works/pi-coding-agent` is an OPTIONAL peerDependency: the Pi
 * runtime injects it, and it is deliberately NOT installed into our
 * node_modules (see package.json `peerDependenciesMeta`). Installing it would
 * pull ~136 transitive packages into a supply-chain-security package, which is
 * exactly the outcome this project exists to prevent.
 *
 * Therefore we declare, by hand, ONLY the surface `src/index.ts` actually uses.
 * This is intentionally NOT a copy of upstream type definitions. Do not vendor
 * upstream `.d.ts` files here. Widen this surface only as SupplyGuard genuinely
 * starts using more of the host API, and keep it hand-written and reviewable.
 */
declare module "@earendil-works/pi-coding-agent" {
  /** Payload delivered to a `tool_call` handler. Narrow, deliberately partial. */
  export interface ToolCallEvent {
    readonly toolName: string;
    readonly args: unknown;
  }

  /**
   * Returning `undefined` means "no opinion, proceed with normal Pi behavior".
   * Enforcement result shapes are intentionally not modelled yet; M1 will
   * introduce them alongside the decision model (ALLOW/WARN/ASK/DENY).
   */
  export type ToolCallEventResult = undefined;

  export interface ExtensionAPI {
    on(
      event: "tool_call",
      handler: (
        event: ToolCallEvent,
      ) => Promise<ToolCallEventResult> | ToolCallEventResult,
    ): void;
  }
}
