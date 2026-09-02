/**
 * Manifest writes caught before they land (SPEC 14, 23.2; M9).
 *
 * Reconciliation compares STATES, so a change made and reverted inside one
 * tool call leaves nothing to compare. This is the other half: reading the
 * command for a write it is about to perform. The negative cases matter as much
 * as the positive ones — a gate that fires on `sed -i README.md` gets disabled.
 */
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { inspectSensitiveWrites, writtenPaths } from "../../src/generic/sensitive-writes.ts";
import { parseShell } from "../../src/generic/shell.ts";
import { createRuntime } from "../../src/index.ts";

const tempRoots: string[] = [];

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

const WATCHED = ["go.mod", "go.sum", "go.work", "go.work.sum", "vendor/modules.txt"];

function writes(command: string): string[] {
  return inspectSensitiveWrites(parseShell(command).commands, WATCHED).map((e) => e.artifact ?? "");
}

test("a redirection into a tracked manifest is a write", () => {
  assert.deepEqual(writes("echo 'require evil v1' >> go.mod"), ["go.mod"]);
  assert.deepEqual(writes("printf x > go.sum"), ["go.sum"]);
  assert.deepEqual(writes("cat other.mod > ./go.mod"), ["go.mod"]);
  assert.deepEqual(writes("echo x > vendor/modules.txt"), ["vendor/modules.txt"]);
});

// A heredoc used to swallow the redirection on its own line, so this exact
// shape wrote a manifest invisibly.
test("a heredoc redirected into a manifest is a write", () => {
  assert.deepEqual(writes("cat <<'EOF' > go.mod\nmodule evil\nEOF"), ["go.mod"]);
  assert.deepEqual(writes("cat > go.mod <<'EOF'\nmodule evil\nEOF"), ["go.mod"]);
});

test("in-place editors, copies and restores are writes", () => {
  assert.deepEqual(writes("sed -i s/v1/v2/ go.mod"), ["go.mod"]);
  assert.deepEqual(writes("sed --in-place s/v1/v2/ go.sum"), ["go.sum"]);
  assert.deepEqual(writes("perl -i -pe s/a/b/ go.mod"), ["go.mod"]);
  assert.deepEqual(writes("cp /tmp/evil.mod go.mod"), ["go.mod"]);
  assert.deepEqual(writes("mv /tmp/evil.mod go.mod"), ["go.mod"]);
  assert.deepEqual(writes("tee go.sum"), ["go.sum"]);
  assert.deepEqual(writes("truncate -s 0 go.sum"), ["go.sum"]);
  // Restoring is overwriting: it is how a temporary substitution disappears.
  assert.deepEqual(writes("git checkout -- go.mod"), ["go.mod"]);
  assert.deepEqual(writes("git restore go.mod"), ["go.mod"]);
});

// The whole point: every step is caught before any of it runs.
test("the substitute-build-revert sequence is gated on the way in", () => {
  assert.deepEqual(
    writes("sed -i s/v1.2.3/v9.9.9/ go.mod && go build ./... && git checkout go.mod"),
    ["go.mod"],
    "reported once, before the command runs at all",
  );
});

test("wrappers and nesting do not hide the write", () => {
  assert.deepEqual(writes("sh -c 'sed -i s/a/b/ go.mod'"), ["go.mod"]);
  assert.deepEqual(writes("cd /repo && sed -i s/a/b/ go.mod"), ["go.mod"]);
  assert.deepEqual(writes("sudo sed -i s/a/b/ go.mod"), ["go.mod"]);
});

// NEGATIVE CORPUS: ordinary development must stay free.
test("ordinary file work is not a manifest write", () => {
  for (const command of [
    "sed -i s/a/b/ README.md",
    "echo hi > /tmp/notes.txt",
    "cp go.mod /tmp/backup.mod",
    "cat go.mod",
    "grep require go.mod",
    "go build ./... > build.log",
    "sed s/a/b/ go.mod",
    "git diff go.mod",
    "git add go.mod",
    "ls -la",
  ]) {
    assert.deepEqual(writes(command), [], command);
  }
});

// `cp go.mod backup` writes `backup`, not `go.mod`; only the destination counts.
test("reading a manifest is not writing one", () => {
  assert.deepEqual(writes("cp go.mod go.mod.bak"), []);
  assert.deepEqual(writes("sed s/a/b/ go.mod > /tmp/out"), []);
});

// `go`'s own manifest-writing subcommands name no file operand, so they are
// not matched here — the Go adapter gates those as dependency events. But the
// tool is not exempt: exempting it would make `go … > go.mod` the one way in.
test("go's own subcommands are not matched, yet go is not a way through", () => {
  assert.deepEqual(writes("go mod edit -require=example.com/x@v1.0.0"), []);
  assert.deepEqual(writes("go mod tidy"), []);
  assert.deepEqual(writes("go list -m all > go.sum"), ["go.sum"]);
  assert.deepEqual(writes("go env > go.mod"), ["go.mod"]);
});

test("nothing is reported when no paths are tracked", () => {
  assert.deepEqual(inspectSensitiveWrites(parseShell("sed -i s/a/b/ go.mod").commands, []), []);
  assert.deepEqual(writtenPaths(parseShell("sed -i s/a/b/ go.mod").commands[0]!, []), []);
});

test("a write is reported once, however many times the command names it", () => {
  const events = inspectSensitiveWrites(
    parseShell("sed -i s/a/b/ go.mod && echo x >> go.mod").commands,
    WATCHED,
  );
  assert.equal(events.length, 1);
  assert.equal(events[0]?.classification, "THIRD_PARTY_MUTATION");
});

test("the whole sequence is blocked end to end, and ordinary work is not", async () => {
  const repo = await mkdtemp(join(tmpdir(), "supplyguard-m9-repo-"));
  const home = await mkdtemp(join(tmpdir(), "supplyguard-m9-home-"));
  tempRoots.push(repo, home);
  await writeFile(join(repo, "go.mod"), "module m\n\ngo 1.22\n\nrequire github.com/foo/bar v1.2.3\n");

  const runtime = createRuntime({
    home,
    env: {},
    proxy: { env: { GOPROXY: "off" } },
    osv: { env: { GOPROXY: "off" } },
    socket: { run: async () => ({ ok: true, stdout: "1.1.163\n" }) },
  });
  const ctx = {
    cwd: repo,
    hasUI: true,
    mode: "tui" as const,
    ui: {
      select: async () => "Deny",
      confirm: async () => false,
      input: async () => undefined,
      notify: () => {},
    },
    sessionManager: { getSessionId: () => "session-1" },
  };
  const call = (command: string) =>
    runtime.onToolCall({ toolName: "bash", toolCallId: "1", input: { command } }, ctx as never);

  await call("ls");

  const blocked = await call(
    "sed -i s/v1.2.3/v9.9.9/ go.mod && go build ./... && git checkout go.mod",
  );
  assert.equal(blocked?.block, true, "the manifest is never written");
  assert.match(blocked?.reason ?? "", /Not approved by a human/);

  for (const ordinary of ["ls -la", "go build ./...", "sed -i s/a/b/ README.md"]) {
    assert.equal(await call(ordinary), undefined, ordinary);
  }
});
