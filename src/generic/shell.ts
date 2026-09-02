/**
 * POSIX-ish shell command parsing (SPEC 10.1).
 *
 * WHY THIS EXISTS
 * ---------------
 * The SPEC is explicit that command interception must not rely on
 * `startsWith("go get")`. An agent can reach the same operation through
 * wrappers, shell composition and nested interpreters:
 *
 *     env FOO=x go get ...
 *     cd dir && go get ...
 *     sh -c 'go get ...'
 *     command go get ...
 *
 * So a command string is tokenized, split into simple commands, and stripped
 * of wrappers before any ecosystem adapter looks at it. This module is
 * ecosystem-agnostic on purpose: the Go adapter uses it today, and the M8
 * generic installer policy (`curl ... | sh`) needs exactly the same
 * pipeline-aware view.
 *
 * WHAT IT IS NOT
 * --------------
 * This is not a shell. It does not expand variables, evaluate substitutions,
 * or resolve $PATH. Where it cannot know something it says so -- `expanded`
 * on a word, `opaque` on the parse -- and callers are expected to treat that
 * as unknown risk rather than as absence of risk. Being unable to read a
 * command is never evidence that the command is safe.
 */

/** A single argument. `expanded` means part of it came from an unquoted `$`. */
export interface ShellWord {
  readonly text: string;
  /** True when the real value is not knowable statically. */
  readonly expanded: boolean;
}

export interface ShellAssignment {
  readonly name: string;
  readonly value: string;
  readonly expanded: boolean;
}

/** One command with its leading `NAME=value` prefix assignments removed. */
export interface SimpleCommand {
  readonly assignments: readonly ShellAssignment[];
  readonly argv: readonly ShellWord[];
  /**
   * Files this command redirects OUTPUT into, e.g. `> go.mod`, `>> go.sum`.
   *
   * Recorded because a redirection is a write, and a write to a manifest is a
   * dependency change however plainly it is spelled. `echo … > go.mod` names no
   * tool SupplyGuard would otherwise recognize.
   */
  readonly writes?: readonly string[];
  /**
   * The operator that preceded this command, e.g. `"|"` or `"&&"`; absent for
   * the first command in a list.
   *
   * Load-bearing for installer-pipeline policy (SPEC 15.2): `curl … | sh` runs
   * whatever the server sends, while `curl … ; sh script.sh` runs a file that
   * is at least on disk to be read. Without the operator the two are the same
   * pair of commands.
   */
  readonly precededBy?: string;
}

export interface ShellParse {
  readonly commands: readonly SimpleCommand[];
  /**
   * True when something in the string could not be read faithfully:
   * command substitution, an unterminated quote, `eval` of a dynamic string.
   * Callers MUST treat this as unknown risk, not as "nothing found".
   */
  readonly opaque: boolean;
  /** Non-secret explanations for `opaque`, suitable for a finding message. */
  readonly notes: readonly string[];
}

/** Word-splitting operators. Everything here separates simple commands. */
const SEPARATORS = new Set([";", ";;", "&&", "||", "|", "|&", "&", "(", ")", "{", "}", "\n"]);

/**
 * Wrappers that prefix another command without changing what it does.
 * Stripping them is what defeats `command go get` and `env FOO=x go get`.
 */
const TRANSPARENT_WRAPPERS = new Set([
  "command",
  "builtin",
  "exec",
  "nohup",
  "setsid",
  "stdbuf",
  "nice",
  "ionice",
  "time",
  "xargs",
  "sudo",
  "doas",
  "proxychains",
  "proxychains4",
]);

/** Interpreters whose `-c` argument is another script to parse. */
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "ash", "busybox"]);

/** Maximum nesting through `sh -c` / `eval`, to bound pathological input. */
const MAX_DEPTH = 8;

/** Maximum command length considered; longer input is reported as opaque. */
const MAX_COMMAND_LENGTH = 128 * 1024;

/** The final path segment of a command word, e.g. `/usr/bin/go` -> `go`. */
export function commandName(word: string): string {
  const cut = word.lastIndexOf("/");
  return cut === -1 ? word : word.slice(cut + 1);
}

interface Token {
  readonly kind: "word" | "op" | "redirect";
  readonly text: string;
  readonly expanded: boolean;
}

interface TokenizeResult {
  readonly tokens: readonly Token[];
  readonly opaque: boolean;
  readonly notes: readonly string[];
}

function isBlank(c: string): boolean {
  return c === " " || c === "\t" || c === "\r";
}

/**
 * Tokenize into words and separator operators.
 *
 * Redirections and heredocs are consumed and discarded: a redirection target
 * is not an argument, and a heredoc body is data being written, not a command
 * being run. Treating a heredoc body as commands would flag `cat <<EOF` blocks
 * that merely write a file.
 */
function tokenize(input: string): TokenizeResult {
  const tokens: Token[] = [];
  const notes: string[] = [];
  let opaque = false;

  let cur = "";
  let started = false;
  let expanded = false;
  let i = 0;

  const flush = (): void => {
    if (started) tokens.push({ kind: "word", text: cur, expanded });
    cur = "";
    started = false;
    expanded = false;
  };

  const pushOp = (text: string): void => {
    flush();
    tokens.push({ kind: "op", text, expanded: false });
  };

  /** Consume a redirection, recording an output target. */
  const consumeRedirect = (): void => {
    // A leading file-descriptor number belongs to the redirection, not to the
    // command: `go build 2>/dev/null` must not gain an argument "2".
    if (started && /^\d+$/.test(cur)) {
      cur = "";
      started = false;
      expanded = false;
    }
    const heredoc = input.startsWith("<<", i) && !input.startsWith("<<<", i);
    // `>` and `>>` write; `<` reads. A heredoc reads, even though it starts
    // with `<<`, and `&>`/`>&` write to a file or a descriptor.
    const writing = !heredoc && input.charAt(i) !== "<";
    while (i < input.length && "<>&".includes(input.charAt(i))) i += 1;
    while (i < input.length && isBlank(input.charAt(i))) i += 1;

    let target = "";
    while (i < input.length && !isBlank(input.charAt(i)) && !"<>|&;\n()".includes(input.charAt(i))) {
      target += input.charAt(i);
      i += 1;
    }

    if (writing && target !== "" && !/^\d+$/.test(target)) {
      tokens.push({ kind: "redirect", text: target, expanded: false });
    }

    if (heredoc) {
      // The rest of THIS line still belongs to the command, and it is where the
      // redirection lives in `cat <<'EOF' > go.mod`. Skipping straight to the
      // delimiter would swallow it, and a heredoc written into a manifest is a
      // manifest write like any other.
      const lineEnd = input.indexOf("\n", i);
      const line = input.slice(i, lineEnd === -1 ? input.length : lineEnd);
      for (const match of line.matchAll(/>>?\s*([^\s<>|&;()]+)/g)) {
        const written = match[1];
        if (written !== undefined && written !== "" && !/^\d+$/.test(written)) {
          tokens.push({ kind: "redirect", text: written, expanded: false });
        }
      }

      // Skip to the line that consists of the delimiter, so the body is not
      // mistaken for commands.
      const delimiter = target.replace(/['"]/g, "").trim();
      const rest = input.slice(i);
      const end = new RegExp(`^[ \\t]*${delimiter.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[ \\t]*$`, "m");
      const match = end.exec(rest);
      if (match === null) {
        i = input.length;
      } else {
        i += (match.index ?? 0) + match[0].length;
      }
    }
  };

  while (i < input.length) {
    const c = input.charAt(i);

    if (c === "\\") {
      if (i + 1 >= input.length) {
        i += 1;
        continue;
      }
      const next = input.charAt(i + 1);
      // A backslash-newline is a line continuation, not a literal.
      if (next !== "\n") {
        cur += next;
        started = true;
      }
      i += 2;
      continue;
    }

    if (c === "'") {
      const end = input.indexOf("'", i + 1);
      if (end === -1) {
        opaque = true;
        notes.push("unterminated single quote");
        break;
      }
      cur += input.slice(i + 1, end);
      started = true;
      i = end + 1;
      continue;
    }

    if (c === '"') {
      i += 1;
      let closed = false;
      while (i < input.length) {
        const d = input.charAt(i);
        if (d === "\\" && i + 1 < input.length) {
          const next = input.charAt(i + 1);
          cur += '"\\$`'.includes(next) ? next : `\\${next}`;
          started = true;
          i += 2;
          continue;
        }
        if (d === '"') {
          closed = true;
          i += 1;
          break;
        }
        if (d === "`") {
          opaque = true;
          notes.push("command substitution inside double quotes");
        }
        if (d === "$" && input.charAt(i + 1) === "(") {
          opaque = true;
          notes.push("command substitution inside double quotes");
        }
        if (d === "$") expanded = true;
        cur += d;
        started = true;
        i += 1;
      }
      started = true;
      if (!closed) {
        opaque = true;
        notes.push("unterminated double quote");
        break;
      }
      continue;
    }

    if (c === "`") {
      opaque = true;
      notes.push("command substitution (backticks)");
      i += 1;
      continue;
    }

    if (c === "$" && input.charAt(i + 1) === "(") {
      opaque = true;
      notes.push("command substitution");
      // Skip the balanced substitution so its interior is not read as commands.
      let depth = 0;
      while (i < input.length) {
        const d = input.charAt(i);
        if (d === "(") depth += 1;
        if (d === ")") {
          depth -= 1;
          if (depth === 0) {
            i += 1;
            break;
          }
        }
        i += 1;
      }
      expanded = true;
      started = true;
      continue;
    }

    if (c === "$") {
      expanded = true;
      started = true;
      cur += c;
      i += 1;
      continue;
    }

    if (c === "#" && !started) {
      const nl = input.indexOf("\n", i);
      i = nl === -1 ? input.length : nl;
      continue;
    }

    if (c === "<" || c === ">") {
      consumeRedirect();
      continue;
    }

    if (isBlank(c)) {
      flush();
      i += 1;
      continue;
    }

    const two = input.slice(i, i + 2);
    if (SEPARATORS.has(two)) {
      pushOp(two);
      i += 2;
      continue;
    }
    if (SEPARATORS.has(c)) {
      pushOp(c);
      i += 1;
      continue;
    }

    cur += c;
    started = true;
    i += 1;
  }

  flush();
  return { tokens, opaque, notes };
}

/** Split a token stream into simple commands at separator operators. */
interface Segment {
  readonly words: ShellWord[];
  /** The operator immediately before this segment, when there was one. */
  readonly precededBy?: string;
  readonly writes: string[];
}

function split(tokens: readonly Token[]): Segment[] {
  const out: Segment[] = [];
  let current: ShellWord[] = [];
  let writes: string[] = [];
  let pending: string | undefined;
  let next: string | undefined;

  const flushSegment = (): void => {
    if (current.length === 0 && writes.length === 0) return;
    out.push({
      words: current,
      writes,
      ...(pending === undefined ? {} : { precededBy: pending }),
    });
    current = [];
    writes = [];
  };

  for (const token of tokens) {
    if (token.kind === "redirect") {
      writes.push(token.text);
      continue;
    }
    if (token.kind === "op") {
      flushSegment();
      // Grouping punctuation does not describe a data connection between two
      // commands, so it must not be mistaken for one.
      pending = token.text === "(" || token.text === ")" || token.text === "{" || token.text === "}"
        ? next
        : token.text;
      next = pending;
      continue;
    }
    current.push({ text: token.text, expanded: token.expanded });
  }
  flushSegment();
  return out;
}

const ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s;

interface Unwrapped {
  readonly command?: SimpleCommand;
  /** Nested scripts discovered in `sh -c` / `eval` arguments. */
  readonly nested: readonly string[];
  readonly opaque: boolean;
  readonly notes: readonly string[];
}

/**
 * Strip prefix assignments and transparent wrappers from one simple command.
 *
 * Returns the innermost real command, plus any nested script strings that must
 * be parsed in their own right.
 */
function unwrap(words: readonly ShellWord[]): Unwrapped {
  const assignments: ShellAssignment[] = [];
  const nested: string[] = [];
  const notes: string[] = [];
  let opaque = false;
  let argv = [...words];

  for (let guard = 0; guard < 32; guard += 1) {
    // Leading NAME=value assignments belong to the command's environment.
    while (argv.length > 0) {
      const head = argv[0];
      if (head === undefined) break;
      const match = ASSIGNMENT.exec(head.text);
      if (match === null) break;
      assignments.push({
        name: match[1] ?? "",
        value: match[2] ?? "",
        expanded: head.expanded,
      });
      argv = argv.slice(1);
    }

    const head = argv[0];
    if (head === undefined) break;

    if (head.expanded) {
      // `$CMD get foo` -- the command name itself is unknown.
      opaque = true;
      notes.push("command name comes from an unresolved expansion");
      break;
    }

    const name = commandName(head.text);

    if (name === "env") {
      argv = argv.slice(1);
      // `env -i`, `env -u NAME`, `env --`; further NAME=value pairs are picked
      // up by the assignment loop on the next iteration.
      while (argv.length > 0) {
        const flag = argv[0];
        if (flag === undefined || !flag.text.startsWith("-")) break;
        const takesValue = flag.text === "-u" || flag.text === "--unset";
        argv = argv.slice(takesValue ? 2 : 1);
        if (flag.text === "--") break;
      }
      continue;
    }

    if (name === "timeout") {
      argv = argv.slice(1);
      // Drop flags and the duration argument.
      while (argv.length > 0) {
        const next = argv[0];
        if (next === undefined) break;
        if (next.text.startsWith("-")) {
          argv = argv.slice(1);
          continue;
        }
        // `timeout -k 5 30s cmd` leaves two duration-shaped words, not one.
        if (/^[\d.]+[smhd]?$/.test(next.text)) {
          argv = argv.slice(1);
          continue;
        }
        break;
      }
      continue;
    }

    if (TRANSPARENT_WRAPPERS.has(name)) {
      argv = argv.slice(1);
      while (argv.length > 0) {
        const flag = argv[0];
        if (flag === undefined || !flag.text.startsWith("-")) break;
        argv = argv.slice(1);
        // A separated numeric value belongs to the flag, not to the command:
        // `nice -n 10 go get`, `xargs -n 1 go get`. A bare number is never a
        // program name, so consuming it cannot swallow a real command. A
        // NON-numeric value is deliberately left in place (`sudo -u root go`),
        // where stopping early leaves a `go` word for the safety net to catch.
        const value = argv[0];
        if (value !== undefined && /^\d+$/.test(value.text) && argv.length > 1) {
          argv = argv.slice(1);
        }
      }
      continue;
    }

    if (SHELLS.has(name)) {
      // `-c`, but also combined forms: `sh -lc '...'`, `bash -xc '...'`.
      const cIndex = argv.findIndex(
        (w) => /^-[a-z]*c[a-z]*$/.test(w.text) && w.text !== "--",
      );
      const script = cIndex === -1 ? undefined : argv[cIndex + 1];
      if (script !== undefined) {
        if (script.expanded) {
          opaque = true;
          notes.push("nested shell script comes from an unresolved expansion");
        } else {
          nested.push(script.text);
        }
        return { nested, opaque, notes };
      }
      break;
    }

    if (name === "eval") {
      const parts = argv.slice(1);
      if (parts.length === 0) break;
      if (parts.some((w) => w.expanded)) {
        opaque = true;
        notes.push("eval of a dynamically built string");
        return { nested, opaque, notes };
      }
      nested.push(parts.map((w) => w.text).join(" "));
      return { nested, opaque, notes };
    }

    break;
  }

  if (argv.length === 0) {
    return assignments.length === 0
      ? { nested, opaque, notes }
      : { command: { assignments, argv: [] }, nested, opaque, notes };
  }

  return { command: { assignments, argv }, nested, opaque, notes };
}

/**
 * Parse a shell command string into the simple commands it would run.
 *
 * Never throws. An unreadable string yields `opaque: true`, which callers must
 * treat as unknown risk.
 */
export function parseShell(command: string, depth = 0): ShellParse {
  if (depth > MAX_DEPTH) {
    return { commands: [], opaque: true, notes: ["shell nesting is too deep to analyze"] };
  }
  if (command.length > MAX_COMMAND_LENGTH) {
    return { commands: [], opaque: true, notes: ["command is too long to analyze"] };
  }

  const tokenized = tokenize(command);
  const commands: SimpleCommand[] = [];
  const notes: string[] = [...tokenized.notes];
  let opaque = tokenized.opaque;

  for (const segment of split(tokenized.tokens)) {
    const result = unwrap(segment.words);
    if (result.opaque) opaque = true;
    notes.push(...result.notes);
    if (result.command !== undefined) {
      commands.push({
        ...result.command,
        ...(segment.precededBy === undefined ? {} : { precededBy: segment.precededBy }),
        ...(segment.writes.length === 0 ? {} : { writes: segment.writes }),
      });
    }

    for (const script of result.nested) {
      const inner = parseShell(script, depth + 1);
      commands.push(...inner.commands);
      if (inner.opaque) opaque = true;
      notes.push(...inner.notes);
    }
  }

  return { commands, opaque, notes: [...new Set(notes)] };
}

/**
 * Does `name` appear as a word in a parsed command WITHOUT being the command
 * being run?
 *
 * This is the safety net behind the parser, not a substitute for it. If a
 * command contains a bare `go` word that did not end up in head position,
 * some wrapper was not modelled -- `weirdwrapper go get foo@latest` -- and
 * concluding "no Go command here" would be exactly wrong.
 *
 * It reads parsed words rather than the raw string, so quoted prose such as
 * `echo 'go for it'` does not trip it: that is one word, not the word `go`.
 */
export function hasUnresolvedCommandWord(
  commands: readonly SimpleCommand[],
  name: string,
): boolean {
  return commands.some((command) =>
    command.argv.some(
      (word, index) => index > 0 && !word.expanded && commandName(word.text) === name,
    ),
  );
}
