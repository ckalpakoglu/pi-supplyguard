/**
 * The shell parser (SPEC 10.1).
 *
 * Tested directly as well as through the Go adapter, because M8's generic
 * installer policy (`curl ... | sh`) will depend on the same pipeline view.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { commandName, parseShell, type SimpleCommand } from "../../src/generic/shell.ts";

function argv(command: SimpleCommand): string[] {
  return command.argv.map((w) => w.text);
}

function commands(input: string): string[][] {
  return parseShell(input).commands.map(argv);
}

test("commandName takes the final path segment", () => {
  assert.equal(commandName("go"), "go");
  assert.equal(commandName("/usr/local/bin/go"), "go");
  assert.equal(commandName("./go"), "go");
  assert.equal(commandName("gofmt"), "gofmt");
});

test("a simple command becomes one argv", () => {
  assert.deepEqual(commands("go build ./..."), [["go", "build", "./..."]]);
});

test("composition splits into separate commands", () => {
  assert.deepEqual(commands("a && b"), [["a"], ["b"]]);
  assert.deepEqual(commands("a; b"), [["a"], ["b"]]);
  assert.deepEqual(commands("a || b"), [["a"], ["b"]]);
  assert.deepEqual(commands("a | b"), [["a"], ["b"]]);
  assert.deepEqual(commands("a & b"), [["a"], ["b"]]);
  assert.deepEqual(commands("a\nb"), [["a"], ["b"]]);
  assert.deepEqual(commands("(a) && { b; }"), [["a"], ["b"]]);
});

test("prefix assignments are separated from the command", () => {
  const [first] = parseShell("FOO=1 BAR=2 go build").commands;
  assert.deepEqual(argv(first as SimpleCommand), ["go", "build"]);
  assert.deepEqual(
    (first as SimpleCommand).assignments.map((a) => [a.name, a.value]),
    [
      ["FOO", "1"],
      ["BAR", "2"],
    ],
  );
});

test("an assignment with no command is still reported", () => {
  const [first] = parseShell("GOSUMDB=off").commands;
  assert.deepEqual(argv(first as SimpleCommand), []);
  assert.equal((first as SimpleCommand).assignments[0]?.name, "GOSUMDB");
});

test("quotes are removed and their content stays one word", () => {
  assert.deepEqual(commands("echo 'a b'"), [["echo", "a b"]]);
  assert.deepEqual(commands('echo "a b"'), [["echo", "a b"]]);
  assert.deepEqual(commands("echo a\\ b"), [["echo", "a b"]]);
  assert.deepEqual(commands(`echo "it's"`), [["echo", "it's"]]);
});

test("nested shells are flattened into the command list", () => {
  assert.deepEqual(commands("sh -c 'go build'"), [["go", "build"]]);
  assert.deepEqual(commands("sh -c 'a && b'"), [["a"], ["b"]]);
  assert.deepEqual(commands("bash -lc 'go build'"), [["go", "build"]]);
});

test("redirections and their targets are not arguments", () => {
  assert.deepEqual(commands("go build > out.log"), [["go", "build"]]);
  assert.deepEqual(commands("go build 2>/dev/null"), [["go", "build"]]);
  assert.deepEqual(commands("go build >out 2>&1"), [["go", "build"]]);
  assert.deepEqual(commands("cat < in.txt"), [["cat"]]);
});

test("a heredoc body is skipped, not parsed as commands", () => {
  const parsed = parseShell("cat <<EOF > f\nrm -rf /\nEOF\nls");
  assert.deepEqual(
    parsed.commands.map(argv),
    [["cat"], ["ls"]],
    "the body is data being written",
  );
});

test("comments are ignored", () => {
  assert.deepEqual(commands("go build # then ship it"), [["go", "build"]]);
});

test("line continuations join a command", () => {
  assert.deepEqual(commands("go build \\\n  ./..."), [["go", "build", "./..."]]);
});

// SECURITY: what cannot be read must be reported, never silently dropped.
test("command substitution marks the parse opaque", () => {
  for (const input of ["a $(b)", "a `b`", 'a "$(b)"']) {
    assert.ok(parseShell(input).opaque, input);
  }
});

test("unterminated quotes mark the parse opaque", () => {
  assert.ok(parseShell("echo 'unclosed").opaque);
  assert.ok(parseShell('echo "unclosed').opaque);
});

test("an expanded word is flagged as not statically knowable", () => {
  const [first] = parseShell("go get foo@$VERSION").commands;
  const version = (first as SimpleCommand).argv[2];
  assert.equal(version?.expanded, true);
});

test("a command name from an expansion makes the parse opaque", () => {
  assert.ok(parseShell("$CMD build").opaque);
});

test("eval of a literal string is parsed; eval of a dynamic one is opaque", () => {
  assert.deepEqual(commands("eval 'go build'"), [["go", "build"]]);
  assert.ok(parseShell('eval "$DYNAMIC"').opaque);
});

test("the nesting guard reports opaque rather than returning silence", () => {
  // Called past the limit directly: single quotes do not nest in shell, so a
  // genuinely deep script cannot be built by repeated single-quoting.
  const parsed = parseShell("go get foo@latest", 99);
  assert.ok(parsed.opaque);
  assert.deepEqual(parsed.commands, [], "no commands, but flagged, never silent");
});

test("deeply nested interpreters do not blow the stack", () => {
  let input = "go build";
  for (let i = 0; i < 200; i += 1) input = `sh -c "${input}"`;
  assert.doesNotThrow(() => parseShell(input));
});

test("an absurdly long command is reported rather than analyzed", () => {
  const parsed = parseShell("go build " + "x".repeat(200_000));
  assert.ok(parsed.opaque);
  assert.deepEqual(parsed.commands, []);
});

test("an empty command is not an error", () => {
  assert.deepEqual(parseShell("").commands, []);
  assert.deepEqual(parseShell("   ").commands, []);
  assert.equal(parseShell("").opaque, false);
});
