/**
 * PLACEHOLDER TEST — delete once real tests exist.
 *
 * `node --test test/` fails on a tree containing no test files, so this keeps
 * `npm test` green at the dependency-baseline commit. It asserts nothing about
 * SupplyGuard behavior. Real policy tests arrive with M1 (W1-W4).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

test("placeholder: test runner is wired up", () => {
  assert.equal(true, true);
});
