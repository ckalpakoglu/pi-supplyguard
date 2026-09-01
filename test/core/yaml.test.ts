import assert from "node:assert/strict";
import { test } from "node:test";

import { isEmptyDocument, MAX_YAML_BYTES, parseYaml } from "../../src/core/yaml.ts";

test("parses a simple configuration document", () => {
  const result = parseYaml("profile: hardened\nreleaseAge:\n  minimumDays: 30\n");
  assert.ok(result.ok);
  assert.deepEqual(result.value, { profile: "hardened", releaseAge: { minimumDays: 30 } });
});

test("an empty or comment-only document is not data", () => {
  const result = parseYaml("# just a comment\n");
  assert.ok(result.ok);
  assert.ok(isEmptyDocument(result.value));
  assert.ok(isEmptyDocument(null));
  assert.ok(!isEmptyDocument({}));
});

test("malformed YAML returns an error instead of throwing", () => {
  const result = parseYaml("profile: [unclosed\n");
  assert.ok(!result.ok);
  assert.equal(typeof result.error, "string");
});

test("duplicate keys are rejected rather than silently overriding policy", () => {
  const result = parseYaml("profile: standard\nprofile: paranoid\n");
  assert.ok(!result.ok);
});

test("merge keys are not expanded", () => {
  const result = parseYaml("a: &base\n  profile: paranoid\nb:\n  <<: *base\n");
  assert.ok(result.ok);
  const value = result.value as { b?: Record<string, unknown> };
  assert.ok(value.b !== undefined);
  assert.equal(value.b["profile"], undefined, "merge key must not be expanded");
});

test("alias expansion is bounded (billion-laughs resistance)", () => {
  const bomb = [
    "a: &a [x, x, x, x, x, x, x, x, x, x]",
    "b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]",
    "c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]",
    "d: [*c, *c, *c, *c, *c, *c, *c, *c, *c, *c]",
  ].join("\n");
  const result = parseYaml(bomb);
  assert.ok(!result.ok, "alias bomb must be rejected");
});

test("oversized documents are rejected before parsing", () => {
  const huge = `x: "${"a".repeat(MAX_YAML_BYTES)}"`;
  const result = parseYaml(huge);
  assert.ok(!result.ok);
  assert.match(result.error, /exceeds/);
});
