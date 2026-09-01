/**
 * Adversarial bypass corpus (SPEC 10.1, 23.2).
 *
 * SPEC 10.1 is explicit that the parser "must not rely on
 * `startsWith("go get")`". Every entry here is a way an agent could reach the
 * same operation through wrappers, composition or a nested interpreter. If one
 * of these ever starts passing, the command gate is decorative.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { analyzeCommand } from "../../src/adapters/go/commands.ts";
import { parseShell } from "../../src/generic/shell.ts";

/** The operation must be caught: denied outright, or at least gated. */
function assertDenied(command: string): void {
  const analysis = analyzeCommand(command);
  const denied = analysis.operations.some((op) => op.minimumDecision === "deny");
  assert.ok(denied, `must be denied: ${command}`);
}

/** The operation must at minimum not be classified as harmless. */
function assertNotIgnored(command: string): void {
  const analysis = analyzeCommand(command);
  assert.notEqual(
    analysis.classification,
    "SUPPLY_CHAIN_IRRELEVANT",
    `must not be ignored: ${command}`,
  );
}

// ---------------------------------------------------------------------------
// The four wrapper forms named in SPEC 10.1, applied to a denied operation.
// ---------------------------------------------------------------------------

test("SPEC 10.1 wrapper forms cannot smuggle a floating version past the gate", () => {
  for (const command of [
    "go get github.com/foo/bar@latest",
    "env FOO=x go get github.com/foo/bar@latest",
    "cd /tmp && go get github.com/foo/bar@latest",
    "sh -c 'go get github.com/foo/bar@latest'",
    "command go get github.com/foo/bar@latest",
  ]) {
    assertDenied(command);
  }
});

test("the SPEC 23.2 bypass corpus is caught", () => {
  assertDenied("sh -c 'go get foo@latest'");
  assertDenied("env GOSUMDB=off go test ./...");
  assertDenied("cd x && go get foo@latest");
  assertDenied("command go get foo@latest");
});

// ---------------------------------------------------------------------------
// Composition and nesting
// ---------------------------------------------------------------------------

test("every branch of a composed command is inspected", () => {
  for (const command of [
    "go build ./... && go get github.com/foo/bar@latest",
    "go get github.com/foo/bar@latest || true",
    "make deps; go get github.com/foo/bar@latest",
    "go build ./... | tee log && go install example.com/t@latest",
    "(cd sub && go get github.com/foo/bar@latest)",
    "{ go get github.com/foo/bar@latest; }",
    "go vet ./... &\ngo get github.com/foo/bar@latest",
  ]) {
    assertDenied(command);
  }
});

test("nested interpreters are parsed, including combined flags", () => {
  for (const command of [
    "sh -c 'go get foo@latest'",
    'bash -c "go get foo@latest"',
    "bash -lc 'go get foo@latest'",
    "bash -xc 'go get foo@latest'",
    "/bin/sh -c 'go get foo@latest'",
    "zsh -c 'go get foo@latest'",
    "sh -c 'sh -c \"go get foo@latest\"'",
    "eval 'go get foo@latest'",
  ]) {
    assertDenied(command);
  }
});

test("transparent wrappers are stripped", () => {
  for (const command of [
    "command go get foo@latest",
    "exec go get foo@latest",
    "nohup go get foo@latest",
    "time go get foo@latest",
    "sudo go get foo@latest",
    "timeout 30 go get foo@latest",
    "timeout -k 5 30s go get foo@latest",
    "nice -n 10 go get foo@latest",
    "/usr/local/bin/go get foo@latest",
  ]) {
    assertDenied(command);
  }
});

test("env is unwrapped through its own flags", () => {
  for (const command of [
    "env go get foo@latest",
    "env FOO=x go get foo@latest",
    "env -i go get foo@latest",
    "env -u HOME go get foo@latest",
    "env -- go get foo@latest",
    "env FOO=x BAR=y go get foo@latest",
  ]) {
    assertDenied(command);
  }
});

test("quoting and escaping do not hide the operation", () => {
  for (const command of [
    "go get 'github.com/foo/bar@latest'",
    'go get "github.com/foo/bar@latest"',
    "'go' get github.com/foo/bar@latest",
    '"go" get github.com/foo/bar@latest',
  ]) {
    assertDenied(command);
  }
});

// NOT a bypass: `go\ get` is a single word naming a program called "go get",
// which does not exist. The shell would fail before anything was fetched.
test("an escaped space names no program, so it is not a go invocation", () => {
  const analysis = analyzeCommand("go\\ get github.com/foo/bar@latest");
  assert.equal(analysis.classification, "SUPPLY_CHAIN_IRRELEVANT");
});

test("redirection does not consume the operation", () => {
  for (const command of [
    "go get foo@latest > /dev/null",
    "go get foo@latest 2>/dev/null",
    "go get foo@latest >/dev/null 2>&1",
    "go get foo@latest &> log.txt",
  ]) {
    assertDenied(command);
  }
});

test("a checksum bypass is caught however it is spelled", () => {
  for (const command of [
    "GOSUMDB=off go build ./...",
    "env GOSUMDB=off go build ./...",
    "sh -c 'GOSUMDB=off go build ./...'",
    "GOSUMDB='off' go build ./...",
    'GOSUMDB="off" go build ./...',
    "cd x && GOSUMDB=off go test ./...",
    "go env -w GOSUMDB=off",
    "sh -c 'go env -w GOSUMDB=off'",
  ]) {
    assertDenied(command);
  }
});

// ---------------------------------------------------------------------------
// Fail conservative: unreadable is not the same as safe.
// ---------------------------------------------------------------------------

test("an unmodelled wrapper leaves a bare `go` word and is not ignored", () => {
  // `weirdwrapper` is not in the wrapper table. The safety net must notice
  // that a `go` word ended up in an argument position.
  const analysis = analyzeCommand("weirdwrapper go get foo@latest");
  assert.equal(analysis.classification, "UNKNOWN_RISK");
});

test("command substitution makes the parse opaque, not empty", () => {
  for (const command of [
    "go get $(cat version.txt)",
    "go get `cat version.txt`",
    'go get "$(cat version.txt)"',
    "eval \"$DYNAMIC\"",
  ]) {
    assertNotIgnored(command);
  }
});

test("an unresolved command name is unknown risk", () => {
  assertNotIgnored("$GOCMD get foo@latest");
});

test("an unterminated quote is opaque rather than silently truncated", () => {
  const parsed = parseShell("go get 'foo@latest");
  assert.ok(parsed.opaque);
  assert.ok(parsed.notes.length > 0);
});

// ---------------------------------------------------------------------------
// Negative cases: none of the above may turn ordinary work into noise.
// ---------------------------------------------------------------------------

test("a heredoc body is data being written, not a command being run", () => {
  const command = "cat <<'EOF' > install.sh\ngo get foo@latest\nEOF";
  const analysis = analyzeCommand(command);
  assert.equal(
    analysis.classification,
    "SUPPLY_CHAIN_IRRELEVANT",
    "writing a file is not executing it",
  );
});

test("ordinary composed development is not gated", () => {
  for (const command of [
    "go build ./... && go test ./...",
    "cd cmd/server && go build .",
    "gofmt -l . && go vet ./...",
    "git status && ls -la",
    "sh -c 'go test ./...'",
    "go test ./... 2>&1 | tee test.log",
  ]) {
    const analysis = analyzeCommand(command);
    assert.ok(
      analysis.operations.every((op) => op.minimumDecision === undefined),
      `must not be denied: ${command}`,
    );
  }
});

test("a pinned dependency addition survives every wrapper unchanged", () => {
  for (const command of [
    "go get github.com/foo/bar@v1.7.2",
    "env FOO=x go get github.com/foo/bar@v1.7.2",
    "cd /tmp && go get github.com/foo/bar@v1.7.2",
    "sh -c 'go get github.com/foo/bar@v1.7.2'",
  ]) {
    const analysis = analyzeCommand(command);
    assert.equal(analysis.classification, "THIRD_PARTY_MUTATION", command);
    assert.ok(
      analysis.operations.every((op) => op.minimumDecision === undefined),
      `an exact version must not be denied: ${command}`,
    );
    assert.equal(analysis.operations[0]?.version, "v1.7.2", command);
  }
});
