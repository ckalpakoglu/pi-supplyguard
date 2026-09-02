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
 *
 * Verified against the host's `dist/core/extensions/types.d.ts`. If the host
 * API diverges from these declarations, fix this file rather than casting at
 * the call site.
 */
declare module "@earendil-works/pi-coding-agent" {
  /** How the session is being driven. `json`/`print` have no interactive UI. */
  export type ExtensionMode = "tui" | "rpc" | "json" | "print";

  export type NotifyLevel = "info" | "warning" | "error";

  export interface UIPromptOptions {
    signal?: AbortSignal;
    /** Milliseconds. On timeout: select/input resolve undefined, confirm false. */
    timeout?: number;
  }

  export interface ExtensionUI {
    select(
      title: string,
      options: readonly string[],
      opts?: UIPromptOptions,
    ): Promise<string | undefined>;
    confirm(title: string, message: string, opts?: UIPromptOptions): Promise<boolean>;
    input(
      title: string,
      placeholder?: string,
      opts?: UIPromptOptions,
    ): Promise<string | undefined>;
    notify(message: string, level?: NotifyLevel): void | Promise<void>;
  }

  export interface SessionManager {
    getSessionId(): string;
  }

  export interface ExtensionContext {
    readonly cwd: string;
    /**
     * False in `json`/`print` mode, where UI methods are no-ops. Security
     * decisions that need a human MUST check this and fail closed.
     */
    readonly hasUI: boolean;
    readonly mode: ExtensionMode;
    readonly ui: ExtensionUI;
    readonly sessionManager: SessionManager;
  }

  /** Payload delivered to a `tool_call` handler, before the tool executes. */
  export interface ToolCallEvent {
    readonly toolName: string;
    readonly toolCallId?: string;
    /**
     * Tool arguments. MUTABLE by design in the host: a handler may rewrite the
     * call. SupplyGuard never does -- see the bypass note in `src/index.ts`.
     */
    input: Record<string, unknown>;
  }

  /**
   * Returning `undefined` means "no opinion, proceed".
   * Returning `{ block: true }` prevents the tool from executing.
   */
  export interface ToolCallEventResult {
    block?: boolean;
    reason?: string;
    terminate?: boolean;
  }

  export type ToolCallHandler = (
    event: ToolCallEvent,
    ctx: ExtensionContext,
  ) =>
    | Promise<ToolCallEventResult | undefined | void>
    | ToolCallEventResult
    | undefined
    | void;

  /** Text returned to the model from a tool. */
  export interface TextContent {
    type: "text";
    text: string;
  }

  export interface AgentToolResult {
    content: TextContent[];
    details?: unknown;
    isError?: boolean;
  }

  /**
   * Parameter schema for a registered tool.
   *
   * The host types this as a TypeBox `TSchema`, and injects `typebox` as a
   * virtual module for extensions. We declare the plain JSON-Schema shape
   * instead and hand-write the object: the host passes `parameters` straight
   * through to the model as the tool's schema, and importing a schema builder
   * to produce an object literal would add a dependency surface for nothing.
   *
   * SECURITY: this schema is a hint to the model, not a guarantee. Arguments
   * arriving at `execute` are untrusted input and are validated there.
   */
  export interface ToolParameterSchema {
    type: "object";
    properties: Record<string, unknown>;
    required?: readonly string[];
    additionalProperties?: boolean;
  }

  export interface ToolDefinition {
    /** Tool name used in LLM tool calls. */
    name: string;
    /** Human-readable label for the UI. */
    label: string;
    /** Description shown to the model. */
    description: string;
    /** One-line entry in the system prompt's Available tools section. */
    promptSnippet?: string;
    /** Guideline bullets appended to the system prompt while this tool is active. */
    promptGuidelines?: string[];
    parameters: ToolParameterSchema;
    execute(
      toolCallId: string,
      params: unknown,
      signal: AbortSignal | undefined,
      onUpdate: unknown,
      ctx: ExtensionContext,
    ): Promise<AgentToolResult>;
  }

  export interface CommandDefinition {
    description?: string;
    handler: (args: string, ctx: ExtensionContext) => Promise<void> | void;
  }

  export interface ExtensionAPI {
    /** Handlers are awaited; blocking is guaranteed before tool execution. */
    on(event: "tool_call", handler: ToolCallHandler): void;
    registerCommand(name: string, definition: CommandDefinition): void;
    registerTool(tool: ToolDefinition): void;
  }
}
