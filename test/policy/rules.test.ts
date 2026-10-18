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

import { COMPILED_SAFE_MINIMUMS, tightenConfig } from "../../src/core/config.ts";
import { createRuntime } from "../../src/index.ts";
import { matchPolicyRules, normalizeOperand } from "../../src/policy/match.ts";
import { parsePolicyRules } from "../../src/policy/rules.ts";

const tempRoots: string[] = [];

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

// ---------------------------------------------------------------------------
// Schema and layering
// ---------------------------------------------------------------------------

test("valid rules load; every rejected entry is announced", () => {
  const { rules, warnings } = parsePolicyRules(
    [
      { id: "a", decision: "deny", match: { command: "kubectl", argsContain: ["delete"] }, reason: "prod" },
      { id: "b", decision: "ask", match: { writePrefix: "infra/" } },
      { decision: "deny", match: { command: "x" } }, // no id
      { id: "c", decision: "allow", match: { command: "x" } }, // a rule may only tighten
      { id: "d", decision: "maybe", match: { command: "x" } },
      { id: "e", decision: "deny", match: { regex: ".*" } }, // unknown matcher
      { id: "f", decision: "deny" }, // no match
      "not a mapping",
      { id: "g", decision: "deny", match: { argsContain: [] } },
    ],
    "project",
  );

  assert.deepEqual(rules.map((rule) => rule.id), ["a", "b"], "only the valid rules load");
  assert.equal(rules[0]?.reason, "prod");
  for (let index = 2; index <= 8; index += 1) {
    assert.ok(
      warnings.some((w) => w.startsWith(`policies[${index}]`)),
      `rejected entry ${index} is announced, not swallowed`,
    );
  }
  assert.ok(!warnings.some((w) => /^policies\[[01]\]/.test(w)), "valid entries raise nothing");
});

test("a project rule reusing a global rule's id cannot displace it", () => {
  // The tighten-only hole this closes: dedupe-by-id let a "stricter" project
  // rule with the same id and a match that never fires REPLACE the
  // operator's global rule -- a deny that disabled an ask.
  const global = tightenConfig(
    COMPILED_SAFE_MINIMUMS,
    { policyRules: parsePolicyRules([{ id: "prod", decision: "ask", match: { command: "kubectl" } }], "global").rules },
    "global configuration",
  ).config;
  const project = tightenConfig(
    global,
    { policyRules: parsePolicyRules([{ id: "prod", decision: "deny", match: { command: "nothing-real" } }], "project").rules },
    "project configuration",
  ).config;

  const tripped = matchPolicyRules(
    { toolName: "bash", input: { command: "kubectl delete ns prod" } },
    project.policyRules,
    "/repo",
  );
  assert.deepEqual(tripped.map((rule) => rule.source), ["global"], "the global rule still fires");
});

// ---------------------------------------------------------------------------
// Matchers
// ---------------------------------------------------------------------------

test("path normalization: one form inside the repo, honest absolutes outside", () => {
  assert.equal(normalizeOperand("./infra/x", "/repo"), "infra/x");
  assert.equal(normalizeOperand("infra/../infra/x", "/repo"), "infra/x");
  assert.equal(normalizeOperand("/repo/infra/x", "/repo"), "infra/x");
  assert.equal(normalizeOperand("/etc/passwd", "/repo"), "/etc/passwd");
  assert.equal(normalizeOperand("../infra/x", "/repo"), "/infra/x", "outside the repo is not inside it");
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
    matchPolicyRules({ toolName, input }, rules, "/repo").map((rule) => rule.id);

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
  assert.ok(
    notices.some((notice) => notice.includes('"bad"')),
    "the rejected rule is announced by id, not swallowed",
  );
});
