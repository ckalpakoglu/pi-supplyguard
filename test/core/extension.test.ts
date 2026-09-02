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

test("the default export registers the tool_call hook and both commands", () => {
  const events: string[] = [];
  const commands: string[] = [];

  supplyguard({
    on: (event: string) => {
      events.push(event);
    },
    registerCommand: (name: string) => {
      commands.push(name);
    },
  } as never);

  assert.deepEqual(events, ["tool_call"], "the gate is the whole point");
  assert.deepEqual(commands, ["supplyguard-status", "supplyguard-profile"]);
});
