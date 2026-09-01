import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import {
  appendAuditRecord,
  createAuditSink,
  detectGitBranch,
  redact,
  REDACTED,
  type AuditRecord,
} from "../../src/core/audit.ts";

const tempRoots: string[] = [];

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "supplyguard-audit-"));
  tempRoots.push(dir);
  return dir;
}

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

function baseRecord(): AuditRecord {
  return {
    timestamp: "2026-09-01T00:00:00.000Z",
    kind: "tool-call",
    profile: "hardened",
    session: "session-1",
    cwd: "/repo",
    headless: false,
    tool: "bash",
    decision: "deny",
  };
}

// SECURITY INVARIANT: secrets never reach durable records (SPEC 18.3).
test("sensitive keys are redacted regardless of value", () => {
  const redacted = redact({
    token: "abc",
    apiKey: "abc",
    api_key: "abc",
    Authorization: "Basic abc",
    socketApiToken: "abc",
    password: "hunter2",
    NPM_TOKEN: "abc",
    private_key: "abc",
    cookie: "a=b",
    credentials: { user: "x" },
  }) as Record<string, unknown>;

  for (const key of Object.keys(redacted)) {
    assert.equal(redacted[key], REDACTED, `${key} must be redacted`);
  }
});

test("environment containers are never dumped", () => {
  const redacted = redact({
    env: { PATH: "/usr/bin", GITHUB_TOKEN: "ghp_aaaaaaaaaaaaaaaaaaaa" },
    environment: { X: "y" },
    headers: { authorization: "Bearer abc" },
  }) as Record<string, unknown>;

  assert.equal(redacted["env"], REDACTED);
  assert.equal(redacted["environment"], REDACTED);
  assert.equal(redacted["headers"], REDACTED);
  assert.ok(!JSON.stringify(redacted).includes("ghp_"));
});

test("secret-shaped values are redacted even under innocuous keys", () => {
  const samples = [
    "ghp_abcdefghijklmnopqrstuvwxyz012345",
    "github_pat_11ABCDEFG0abcdefghijklmnop",
    "sk-abcdefghijklmnopqrstuvwxyz",
    "xoxb-123456789012-abcdefghijkl",
    "AKIAIOSFODNN7EXAMPLE",
    "Bearer abcdefghijklmnopqrstuvwxyz012345",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
  ];
  for (const sample of samples) {
    const out = redact({ note: sample }) as Record<string, unknown>;
    assert.equal(out["note"], REDACTED, sample);
  }
});

test("ordinary values survive redaction", () => {
  const out = redact({
    artifact: "example.test/module",
    version: "v1.7.2",
    releaseAgeDays: 94,
    vendored: true,
    findings: [{ decision: "deny", message: "blocked" }],
  }) as Record<string, unknown>;

  assert.equal(out["artifact"], "example.test/module");
  assert.equal(out["version"], "v1.7.2");
  assert.equal(out["releaseAgeDays"], 94);
  assert.equal(out["vendored"], true);
  assert.deepEqual(out["findings"], [{ decision: "deny", message: "blocked" }]);
});

test("redaction bounds depth, arrays, strings and object size", () => {
  const deep = { a: { b: { c: { d: { e: { f: { g: "too deep" } } } } } } };
  assert.match(JSON.stringify(redact(deep)), /depth-limited/);

  const long = redact({ note: "a".repeat(5000) }) as Record<string, unknown>;
  assert.match(String(long["note"]), /truncated/);

  const many = redact({ items: Array.from({ length: 500 }, (_, i) => i) }) as Record<
    string,
    unknown
  >;
  assert.equal((many["items"] as unknown[]).length, 51);
});

test("non-serializable values are dropped, not coerced", () => {
  const out = redact({
    fn: () => "x",
    sym: Symbol("x"),
    ok: "kept",
    when: new Date("2026-09-01T00:00:00.000Z"),
    err: new Error("boom"),
  }) as Record<string, unknown>;

  assert.ok(!("fn" in out));
  assert.ok(!("sym" in out));
  assert.equal(out["ok"], "kept");
  assert.equal(out["when"], "2026-09-01T00:00:00.000Z");
  assert.equal(out["err"], "Error: boom");
});

test("audit log is append-only JSONL with restrictive permissions", async () => {
  const dir = await tempDir();
  const path = join(dir, "nested", "audit.jsonl");

  await appendAuditRecord(path, baseRecord());
  await appendAuditRecord(path, { ...baseRecord(), decision: "allow" });

  const lines = (await readFile(path, "utf8")).trim().split("\n");
  assert.equal(lines.length, 2);
  const first = JSON.parse(lines[0] ?? "{}") as Record<string, unknown>;
  assert.equal(first["decision"], "deny");
  assert.equal(first["profile"], "hardened");
  assert.equal(JSON.parse(lines[1] ?? "{}")["decision"], "allow");

  const mode = (await stat(path)).mode & 0o777;
  assert.equal(mode & 0o077, 0, "audit log must not be group/other readable");
});

test("records are redacted on the way to disk", async () => {
  const dir = await tempDir();
  const path = join(dir, "audit.jsonl");
  const sink = createAuditSink(path);

  await sink({
    ...baseRecord(),
    message: "token is ghp_abcdefghijklmnopqrstuvwxyz012345",
    notes: ["ok"],
  });

  const text = await readFile(path, "utf8");
  assert.ok(!text.includes("ghp_"), "secret-shaped value leaked into the audit log");
  assert.match(text, /redacted/);
});

test("git branch detection reads .git without spawning a process", async () => {
  const dir = await tempDir();
  await mkdir(join(dir, ".git"), { recursive: true });
  await writeFile(join(dir, ".git", "HEAD"), "ref: refs/heads/feature/x\n");
  assert.equal(await detectGitBranch(dir), "feature/x");

  const worktree = await tempDir();
  await writeFile(join(worktree, ".git"), `gitdir: ${join(dir, ".git")}\n`);
  assert.equal(await detectGitBranch(worktree), "feature/x");
});

test("git branch detection returns undefined rather than inventing facts", async () => {
  const dir = await tempDir();
  assert.equal(await detectGitBranch(dir), undefined);
});
