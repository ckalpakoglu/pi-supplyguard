/**
 * The extension entry point itself (SPEC 19).
 *
 * `src/index.ts` is loaded by Pi through Node's native type stripping, which
 * erases types without evaluating them: a construct needing emit, or an import
 * of the host package at runtime, breaks at LOAD time — before any policy runs,
 * and in a way no unit test of `createRuntime` would catch. This test imports
 * the module the way the host does and checks that it registers what it claims.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import supplyguard from "../../src/index.ts";

test("the default export registers the tool_call hook, the commands and the tool", () => {
  const events: string[] = [];
  const commands: string[] = [];
  const tools: { name: string; parameters: unknown }[] = [];

  supplyguard({
    on: (event: string) => {
      events.push(event);
    },
    registerCommand: (name: string) => {
      commands.push(name);
    },
    registerTool: (tool: { name: string; parameters: unknown }) => {
      tools.push(tool);
    },
  } as never);

  assert.deepEqual(events, ["tool_call"], "the gate is the whole point");
  assert.deepEqual(commands, ["supplyguard-status", "supplyguard-profile"]);
  assert.deepEqual(
    tools.map((t) => t.name),
    ["supplyguard_justify_dependency"],
  );

  // The schema reaches the model verbatim, so it has to be plain JSON Schema
  // rather than anything that needs a builder at runtime.
  assert.deepEqual(JSON.parse(JSON.stringify(tools[0]?.parameters)), tools[0]?.parameters);
});
