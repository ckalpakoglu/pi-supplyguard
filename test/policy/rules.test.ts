/**
 * Local policy rules (M15, PLAN-LOCAL-POLICY §3): schema, layering, matching,
 * and the end-to-end path — a rule in `.supplyguard.yaml` gating a call no
 * adapter found interesting.
 *
 * Every rule decision is positive+negative tested (AGENTS.md): the risky
 * shape is gated, the legitimate neighbor proceeds.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { createRuntime } from "../../src/index.ts";
import {
  globToRegExp,
  matchPolicyRules,
  normalizeOperand,
} from "../../src/policy/match.ts";
import {
  mergePolicyRules,
  parsePolicyRules,
  RULE_CAP,
  type PolicyRule,
} from "../../src/policy/rules.ts";

const tempRoots: string[] = [];

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

// ---------------------------------------------------------------------------
// Schema and validation
// ---------------------------------------------------------------------------

test("valid rules load; the shapes that must not load say why", () => {
  const { rules, warnings } = parsePolicyRules(
    [
      { id: "a", decision: "deny", match: { command: "kubectl", argsContain: ["delete"] }, reason: "prod" },
      { id: "b", decision: "ask", match: { writePrefix: "infra/" } },
      { decision: "deny", match: { command: "x" } }, // no id
      { id: "c", decision: "allow", match: { command: "x" } }, // allow is an exception primitive
      { id: "d", decision: "maybe", match: { command: "x" } }, // not a decision
      { id: "e", decision: "deny", match: { regex: ".*" } }, // unknown matcher, no recognized key
      { id: "f", decision: "deny" }, // no match at all
      "not a mapping",
      { id: "g", decision: "deny", match: { argsContain: [] } }, // empty list
    ],
    "project",
  );

  assert.deepEqual(rules.map((rule) => rule.id), ["a", "b"], "only the valid rules load");
  assert.equal(rules[0]?.source, "project");
  assert.equal(rules[0]?.reason, "prod");
  assert.equal(rules[1]?.match.writePrefix, "infra/");

  const joined = warnings.join("\n");
  assert.ok(!warnings.some((w) => w.includes('policies[0]("a")') || w.includes('policies[1]("b")')));
  assert.match(joined, /missing or empty "id"/);
  assert.match(joined, /decision "allow" is not supported/);
  assert.match(joined, /must be one of warn\|ask\|deny/);
  assert.match(joined, /unknown match key "regex"/);
  assert.match(joined, /no recognized key/);
  assert.match(joined, /not a mapping/);
  assert.match(joined, /argsContain must be a non-empty string list/);
});

test("duplicate ids across layers resolve stricter, with a warning either way", () => {
  const global = parsePolicyRules(
    [{ id: "r", decision: "warn", match: { command: "terraform" } }],
    "global",
  ).rules;
  const stricter = parsePolicyRules(
    [{ id: "r", decision: "deny", match: { command: "terraform" } }],
    "project",
  ).rules;
  const weaker = parsePolicyRules(
    [{ id: "r", decision: "warn", match: { command: "terraform" } }],
    "project",
  ).rules;

  const up = mergePolicyRules(global, stricter, "project configuration");
  assert.equal(up.rules.length, 1);
  assert.equal(up.rules[0]?.decision, "deny");
  assert.match(up.warnings.join("\n"), /stricter decision "deny" wins/);

  const flat = mergePolicyRules(
    parsePolicyRules([{ id: "r", decision: "deny", match: { command: "terraform" } }], "global").rules,
    weaker,
    "project configuration",
  );
  assert.equal(flat.rules[0]?.decision, "deny", "a layer may tighten, never weaken");
  assert.match(flat.warnings.join("\n"), /established stricter decision "deny" stands/);
});

test("the rule cap drops the tail loudly", () => {
  const many: PolicyRule[] = Array.from({ length: RULE_CAP + 3 }, (_, i) => ({
    id: `r${i}`,
    source: "project" as const,
    decision: "warn" as const,
    match: { command: `tool-${i}` },
  }));
  const merged = mergePolicyRules([], many, "project configuration");
  assert.equal(merged.rules.length, RULE_CAP);
  assert.match(merged.warnings.join("\n"), new RegExp(`dropped: r${RULE_CAP}, r${RULE_CAP + 1}, r${RULE_CAP + 2}`));
});

// ---------------------------------------------------------------------------
// Matchers
// ---------------------------------------------------------------------------

test("globs stay tiny on purpose", () => {
  assert.ok(globToRegExp("*.tfvars").test("prod.tfvars"));
  assert.ok(!globToRegExp("*.tfvars").test("dir/prod.tfvars"), "* crosses no slash");
  assert.ok(globToRegExp("infra/**").test("infra/live/main.tf"));
  assert.ok(globToRegExp("a?c").test("abc"));
  assert.ok(!globToRegExp("a.c").test("abc"), "a literal dot is a literal dot");
});

test("path normalization defeats ./, a/../ and absolute-inside-repo spellings", () => {
  assert.equal(normalizeOperand("./infra/x", "/repo"), "infra/x");
  assert.equal(normalizeOperand("infra/../infra/x", "/repo"), "infra/x");
  assert.equal(normalizeOperand("/repo/infra/x", "/repo"), "infra/x");
  assert.equal(normalizeOperand("/etc/passwd", "/repo"), "/etc/passwd", "outside stays absolute, honestly");
});

test("matching is wrapper- and nesting-proof, and shape-honest", () => {
  const rules = parsePolicyRules(
    [
      { id: "force", decision: "ask", match: { command: "git", argsContain: ["--force"] } },
      { id: "prod-delete", decision: "deny", match: { command: "kubectl", argsContain: ["delete"] } },
      { id: "infra-write", decision: "deny", match: { writePrefix: "infra/" } },
      { id: "infra-read", decision: "ask", match: { readPrefix: "infra/" } },
      { id: "tfvars", decision: "deny", match: { pathGlob: "*.tfvars" } },
      { id: "edit-tool", decision: "ask", match: { toolName: "edit", pathGlob: "infra/**" } },
    ],
    "project",
  ).rules;

  const match = (toolName: string, input: Record<string, unknown>) =>
    matchPolicyRules({ toolName, input }, rules, "/repo").map((m) => m.rule.id);

  assert.deepEqual(match("bash", { command: "git push --force origin main" }), ["force"]);
  assert.deepEqual(match("bash", { command: "sudo git push --force origin main" }), ["force"], "wrapper");
  assert.deepEqual(match("bash", { command: "env X=y git push --force" }), ["force"], "assignment prefix");
  assert.deepEqual(match("bash", { command: "sh -c 'git push --force'" }), ["force"], "nested shell");
  assert.deepEqual(match("bash", { command: "git push origin main" }), [], "negative: no force flag");

  assert.deepEqual(match("bash", { command: "kubectl delete ns prod" }), ["prod-delete"]);
  assert.deepEqual(match("bash", { command: "sh -c 'kubectl delete ns prod'" }), ["prod-delete"]);
  assert.deepEqual(match("bash", { command: "kubectl get pods" }), [], "negative: read-only kubectl");

  assert.deepEqual(match("bash", { command: "sed -i s/a/b/ infra/main.tf" }), ["infra-write", "infra-read"]);
  assert.deepEqual(match("bash", { command: "cat infra/plan.md" }), ["infra-read"], "a read is not a write");
  assert.deepEqual(match("edit", { path: "infra/main.tf", oldText: "a", newText: "b" }), ["infra-write", "infra-read", "edit-tool"]);
  assert.deepEqual(match("bash", { command: "cat docs/plan.md" }), [], "negative: another tree");

  assert.deepEqual(match("bash", { command: "cat prod.tfvars" }), ["tfvars"]);
  assert.deepEqual(match("bash", { command: "cat ./prod.tfvars" }), ["tfvars"], "./ is normalized");
  assert.deepEqual(match("bash", { command: "cat /repo/prod.tfvars" }), ["tfvars"], "absolute inside the repo");
});

// ---------------------------------------------------------------------------
// End to end: a rule in .supplyguard.yaml gates the real tool-call path
// ---------------------------------------------------------------------------

async function runtimeWithRules(
  policies: readonly unknown[],
  options: { hasUI?: boolean; answer?: string } = {},
) {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-policy-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-policy-home-"));
  tempRoots.push(repo, home);
  await mkdir(join(repo, "infra"), { recursive: true });
  await writeFile(
    join(repo, ".supplyguard.yaml"),
    `version: 1\npolicies:\n${policies
      .map((p) => `  - ${JSON.stringify(p)}`)
      .join("\n")}\n`,
  );

  const prompts: string[] = [];
  const notices: string[] = [];
  const runtime = createRuntime({ home, env: {}, now: () => new Date("2026-10-11T00:00:00.000Z") });
  const ctx = {
    cwd: repo,
    hasUI: options.hasUI ?? true,
    mode: (options.hasUI ?? true) ? ("tui" as const) : ("print" as const),
    ui: {
      select: async (title: string) => {
        prompts.push(title);
        return options.answer;
      },
      confirm: async () => false,
      input: async () => undefined,
      notify: (message: string) => {
        notices.push(message);
      },
    },
    sessionManager: { getSessionId: () => "session-1" },
  };
  return { runtime, ctx, repo, prompts, notices };
}

test("a deny rule blocks a call no adapter found interesting, with the rule named", async () => {
  const { runtime, ctx } = await runtimeWithRules([
    { id: "no-force-push", decision: "deny", match: { command: "git", argsContain: ["--force"] }, reason: "rewrites shared history" },
  ]);

  const blocked = await runtime.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "git push --force origin main" } },
    ctx as never,
  );
  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /no-force-push/);
  assert.match(blocked?.reason ?? "", /rewrites shared history/);

  const fine = await runtime.onToolCall(
    { toolName: "bash", toolCallId: "2", input: { command: "git push origin main" } },
    ctx as never,
  );
  assert.equal(fine?.block, undefined, "negative: the same command without the flag proceeds");
});

test("an ask rule reaches a human when interactive and fails closed headless", async () => {
  const policies = [
    { id: "ask-infra-read", decision: "ask", match: { readPrefix: "infra/" }, reason: "infra is review-only" },
  ];

  const interactive = await runtimeWithRules(policies);
  const asked = await interactive.runtime.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "cat infra/plan.md" } },
    interactive.ctx as never,
  );
  assert.equal(asked?.block, true, "no-response is not approval");
  assert.match(interactive.prompts.join("\n"), /ask-infra-read/);
  assert.match(interactive.prompts.join("\n"), /infra is review-only/);

  const headless = await runtimeWithRules(policies, { hasUI: false });
  const worker = await headless.runtime.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "cat infra/plan.md" } },
    headless.ctx as never,
  );
  assert.equal(worker?.block, true, "a delegated worker cannot pass a human gate");
  assert.deepEqual(headless.prompts, []);
});

test("a warn rule proceeds but is not silent", async () => {
  const { runtime, ctx, prompts } = await runtimeWithRules([
    { id: "warn-terraform", decision: "warn", match: { command: "terraform" } },
  ]);

  const result = await runtime.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "terraform plan" } },
    ctx as never,
  );
  assert.equal(result?.block, undefined, "a warning does not stop the call");
  assert.deepEqual(prompts, [], "and does not ask");
});

test("a rule firing on an otherwise harmless call still gates it (fast-path bypass)", async () => {
  // `git push` is SUPPLY_CHAIN_IRRELEVANT to every adapter: no events, no
  // classification. Before M15 such calls took the unaudited fast path; the
  // rule must fire anyway -- that is the feature.
  const { runtime, ctx } = await runtimeWithRules([
    { id: "no-publish", decision: "deny", match: { command: "npm", argsContain: ["publish"] } },
  ]);

  const blocked = await runtime.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "npm publish" } },
    ctx as never,
  );
  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /no-publish/);
});

test("an invalid rule is ignored loudly while its valid siblings still gate", async () => {
  const { runtime, ctx, notices } = await runtimeWithRules([
    { id: "good", decision: "deny", match: { command: "cargo", argsContain: ["publish"] } },
    { id: "bad", decision: "allow", match: { command: "anything" } },
  ]);

  const blocked = await runtime.onToolCall(
    { toolName: "bash", toolCallId: "1", input: { command: "cargo publish" } },
    ctx as never,
  );
  assert.equal(blocked?.block, true, "the valid rule still gates");
  assert.match(
    notices.join("\n"),
    /decision "allow" is not supported/,
    "the rejected rule is announced, not swallowed",
  );
});
