/**
 * Go command recognition (SPEC 10.1 - 10.3).
 *
 * Pure analysis: this module reads command strings and reports what they would
 * do. It never executes anything and never touches the filesystem.
 *
 * The shell handling that defeats `env FOO=x go get`, `sh -c '...'`,
 * `cd x && ...` and `command go get` lives in `src/generic/shell.ts`; this file
 * only interprets the resulting argv.
 */

import type { Decision } from "../../core/decisions.ts";
import type { SupplyChainEventClass, ToolCallClassification } from "../../core/events.ts";
import {
  commandName,
  hasUnresolvedCommandWord,
  parseShell,
  type ShellAssignment,
  type ShellWord,
} from "../../generic/shell.ts";

export const GO_ECOSYSTEM = "go";

/**
 * An exact Go version: a semantic version, or a full commit hash.
 *
 * Deliberately strict. `v1`, `v1.7`, `latest`, `master`, `upgrade` and branch
 * names all fail, because none of them names one immutable artifact. Go
 * pseudo-versions (`v0.0.0-20230101120000-abcdef123456`) are semver and pass.
 */
const EXACT_VERSION = /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const FULL_COMMIT = /^[0-9a-f]{40}$/;

/** `go get module@none` removes a requirement rather than adding one. */
const REMOVE_VERSION = "none";

export function isExactVersion(version: string): boolean {
  return EXACT_VERSION.test(version) || FULL_COMMIT.test(version);
}

/**
 * Environment variables that weaken Go's module integrity guarantees.
 *
 * SPEC 10.3 and invariant 18: checksum verification is never disabled to make
 * a proxy, scanner or firewall work. `GOPRIVATE` is deliberately absent -- it
 * has a legitimate use for internal modules -- except in its fully wildcard
 * form, which disables verification for everything.
 */
function checksumBypass(name: string, value: string): string | undefined {
  const upper = name.toUpperCase();
  const lower = value.trim().toLowerCase();

  if (upper === "GOSUMDB" && (lower === "off" || lower === "")) {
    return "GOSUMDB=off disables Go checksum database verification";
  }
  if (upper === "GONOSUMDB" || upper === "GONOSUMCHECK") {
    return `${upper} suppresses checksum verification`;
  }
  if (upper === "GOFLAGS" && /(^|\s)-insecure(\s|$)/.test(lower)) {
    return "GOFLAGS contains -insecure";
  }
  if (upper === "GOINSECURE" && lower !== "") {
    return "GOINSECURE disables module transport security";
  }
  if (upper === "GONOSUMDB" || (upper === "GOPRIVATE" && (lower === "*" || lower === "*/*"))) {
    return "GOPRIVATE=* disables checksum verification for every module";
  }
  if (upper === "GONOSUMDB") return "GONOSUMDB suppresses checksum verification";
  return undefined;
}

/** What one recognized Go operation means to the policy engine. */
export interface GoOperation {
  readonly eventClass: SupplyChainEventClass;
  readonly classification: ToolCallClassification;
  readonly summary: string;
  readonly artifact?: string;
  readonly version?: string;
  /**
   * Adapter-asserted floor. Folded into the profile baseline through
   * `mostRestrictive`, so it can only ever tighten (SPEC 6.1).
   */
  readonly minimumDecision?: Decision;
}

export interface GoAnalysis {
  readonly classification: ToolCallClassification;
  readonly operations: readonly GoOperation[];
  /** Non-secret explanations, e.g. why a command could not be read. */
  readonly notes: readonly string[];
  /**
   * True when the command is expected to rewrite go.mod/go.sum/go.work.
   *
   * Used by manifest reconciliation (SPEC 14.2) to tell a file change this
   * command produced from one an editing tool made behind the gate's back.
   * `go mod init` is the reason this is not simply "the call was a mutation":
   * it writes a manifest that contains no third-party trust at all.
   */
  readonly writesManifests: boolean;
}

const IRRELEVANT: GoAnalysis = {
  classification: "SUPPLY_CHAIN_IRRELEVANT",
  operations: [],
  notes: [],
  writesManifests: false,
};

/** `go` subcommands that write go.mod, go.sum, go.work or the vendor tree. */
const MANIFEST_WRITING_SUBCOMMANDS = new Set(["get", "mod", "work"]);

/** Go subcommands that cannot introduce or fetch third-party code. */
const INERT_SUBCOMMANDS = new Set(["version", "doc", "help", "fix", "clean", "tool", "bug"]);

/**
 * Go subcommands that build, test or inspect and may therefore fetch or
 * execute third-party code depending on repository state (SPEC 5.1).
 */
const CAPABLE_SUBCOMMANDS = new Set([
  "build",
  "test",
  "vet",
  "fmt",
  "list",
  "generate",
  "run",
  "install",
  "work",
]);

function text(words: readonly ShellWord[]): string[] {
  return words.map((w) => w.text);
}

/** Split `module@version`, tolerating a bare module path. */
function splitArtifact(spec: string): { artifact: string; version?: string } {
  const at = spec.lastIndexOf("@");
  if (at <= 0) return { artifact: spec };
  return { artifact: spec.slice(0, at), version: spec.slice(at + 1) };
}

function isFlag(word: string): boolean {
  return word.startsWith("-");
}

/**
 * Judge one `module@version` argument for a dependency-shaped operation.
 *
 * The exact-version rule (SPEC 10.2) is enforced here: a bare module path or a
 * floating version is denied outright, and only an exact version proceeds into
 * the normal trust-evaluation pipeline.
 */
function dependencyOperation(
  spec: ShellWord,
  eventClass: SupplyChainEventClass,
  verb: string,
): GoOperation {
  const { artifact, version } = splitArtifact(spec.text);

  if (spec.expanded) {
    return {
      eventClass,
      classification: "THIRD_PARTY_MUTATION",
      artifact,
      summary: `${verb} ${spec.text} where the version comes from an unresolved shell expansion`,
      minimumDecision: "deny",
    };
  }

  if (version === REMOVE_VERSION) {
    return {
      eventClass: "DependencyRemove",
      classification: "THIRD_PARTY_MUTATION",
      artifact,
      version,
      summary: `removes the requirement on ${artifact}`,
    };
  }

  if (version === undefined) {
    return {
      eventClass,
      classification: "THIRD_PARTY_MUTATION",
      artifact,
      summary: `${verb} ${artifact} without an exact version`,
      minimumDecision: "deny",
    };
  }

  if (!isExactVersion(version)) {
    return {
      eventClass,
      classification: "THIRD_PARTY_MUTATION",
      artifact,
      version,
      summary: `${verb} ${artifact} at floating version "${version}"`,
      minimumDecision: "deny",
    };
  }

  return {
    eventClass,
    classification: "THIRD_PARTY_MUTATION",
    artifact,
    version,
    summary: `${verb} ${artifact} at ${version}`,
  };
}

/** Is this argument a local path rather than a remote module? */
function isLocalTarget(spec: string): boolean {
  return spec === "." || spec.startsWith("./") || spec.startsWith("../") || spec === "all";
}

function analyzeGet(args: readonly ShellWord[]): GoOperation[] {
  const flags = text(args).filter(isFlag);
  const targets = args.filter((w) => !isFlag(w.text));
  const upgrading = flags.some((f) => f === "-u" || f.startsWith("-u="));
  const eventClass: SupplyChainEventClass = upgrading ? "DependencyUpgrade" : "DependencyAdd";
  const verb = upgrading ? "upgrades" : "adds";

  if (targets.length === 0) {
    return [
      {
        eventClass,
        classification: "THIRD_PARTY_MUTATION",
        summary: `\`go get\` without an explicit module resolves versions dynamically`,
        minimumDecision: "deny",
      },
    ];
  }

  return targets.map((target) => {
    if (isLocalTarget(target.text) || upgrading) {
      // `go get -u ./...` and `go get -u all` upgrade whatever the resolver
      // picks. There is no exact version to approve.
      if (isLocalTarget(target.text)) {
        return {
          eventClass,
          classification: "THIRD_PARTY_MUTATION",
          artifact: target.text,
          summary: `${verb} dependencies for "${target.text}" without exact versions`,
          minimumDecision: "deny",
        } satisfies GoOperation;
      }
    }
    return dependencyOperation(target, eventClass, verb);
  });
}

function analyzeInstall(args: readonly ShellWord[]): GoOperation[] {
  const targets = args.filter((w) => !isFlag(w.text));
  if (targets.length === 0) {
    // `go install` with no arguments installs the current module.
    return [];
  }
  return targets.map((target) =>
    isLocalTarget(target.text)
      ? ({
          eventClass: "ToolInstall",
          classification: "THIRD_PARTY_CAPABLE",
          artifact: target.text,
          summary: `installs the local package "${target.text}"`,
        } satisfies GoOperation)
      : dependencyOperation(target, "ToolInstall", "installs"),
  );
}

function analyzeRun(args: readonly ShellWord[]): GoOperation[] {
  const targets = args.filter((w) => !isFlag(w.text));
  const first = targets[0];
  if (first === undefined || isLocalTarget(first.text)) return [];

  const { version } = splitArtifact(first.text);
  if (version === undefined && !first.text.includes(".")) {
    // A bare package name in the current module, not a remote module.
    return [];
  }
  return [dependencyOperation(first, "ThirdPartyExecution", "downloads and executes")];
}

function analyzeMod(args: readonly ShellWord[]): GoOperation[] {
  const sub = args[0]?.text;

  if (sub === "download") {
    return [
      {
        eventClass: "DependencyFetch",
        classification: "THIRD_PARTY_MUTATION",
        summary: "downloads module dependencies",
      },
    ];
  }
  if (sub === "tidy") {
    return [
      {
        eventClass: "LockfileMutation",
        classification: "THIRD_PARTY_MUTATION",
        summary: "rewrites go.mod/go.sum and may add or remove requirements",
      },
    ];
  }
  if (sub === "vendor") {
    return [
      {
        eventClass: "DependencyFetch",
        classification: "THIRD_PARTY_MUTATION",
        summary: "populates the vendor tree from module dependencies",
      },
    ];
  }
  if (sub === "edit") {
    return editOperations(args.slice(1), "go.mod");
  }
  // `go mod verify`, `go mod graph`, `go mod why`, `go mod init` are reads or
  // local initialisation.
  return [];
}

function analyzeWork(args: readonly ShellWord[]): GoOperation[] {
  const sub = args[0]?.text;
  if (sub === "edit") return editOperations(args.slice(1), "go.work");
  return [];
}

/** `-require`, `-replace`, `-droprequire`, `-exclude` mutate the graph. */
function editOperations(args: readonly ShellWord[], file: string): GoOperation[] {
  const operations: GoOperation[] = [];

  for (let i = 0; i < args.length; i += 1) {
    const word = args[i];
    if (word === undefined) continue;
    const eq = word.text.indexOf("=");
    const flag = eq === -1 ? word.text : word.text.slice(0, eq);
    const inline = eq === -1 ? undefined : word.text.slice(eq + 1);
    const value = inline ?? args[i + 1]?.text;
    if (inline === undefined && value !== undefined && !isFlag(flag)) continue;

    if (flag === "-require" && value !== undefined) {
      const { artifact, version } = splitArtifact(value);
      operations.push({
        eventClass: "DependencyAdd",
        classification: "THIRD_PARTY_MUTATION",
        artifact,
        summary: `edits ${file} to require ${value}`,
        ...(version === undefined ? {} : { version }),
        ...(version !== undefined && isExactVersion(version)
          ? {}
          : { minimumDecision: "deny" as const }),
      });
    }
    if (flag === "-replace" && value !== undefined) {
      operations.push({
        eventClass: "DependencyReplace",
        classification: "THIRD_PARTY_MUTATION",
        artifact: value.split("=")[0] ?? value,
        summary: `edits ${file} to replace ${value}`,
      });
    }
    if (flag === "-droprequire" && value !== undefined) {
      operations.push({
        eventClass: "DependencyRemove",
        classification: "THIRD_PARTY_MUTATION",
        artifact: value,
        summary: `edits ${file} to drop the requirement on ${value}`,
      });
    }
    if (flag === "-exclude" && value !== undefined) {
      operations.push({
        eventClass: "SecurityGateChange",
        classification: "THIRD_PARTY_MUTATION",
        artifact: value,
        summary: `edits ${file} to exclude ${value}`,
      });
    }
  }

  return operations;
}

/** `go env -w NAME=VALUE` writes persistent Go configuration. */
function analyzeEnv(args: readonly ShellWord[]): GoOperation[] {
  const operations: GoOperation[] = [];
  const writing = args.some((w) => w.text === "-w");
  const unsetting = args.some((w) => w.text === "-u");
  if (!writing && !unsetting) return [];

  for (const word of args) {
    if (isFlag(word.text)) continue;
    const eq = word.text.indexOf("=");
    const name = eq === -1 ? word.text : word.text.slice(0, eq);
    const value = eq === -1 ? "" : word.text.slice(eq + 1);

    const bypass = checksumBypass(name, value);
    if (bypass !== undefined) {
      operations.push({
        eventClass: "ChecksumBypass",
        classification: "THIRD_PARTY_MUTATION",
        artifact: name,
        summary: `\`go env -w\` ${bypass}`,
        minimumDecision: "deny",
      });
      continue;
    }
    operations.push({
      eventClass: "SecurityGateChange",
      classification: "THIRD_PARTY_MUTATION",
      artifact: name,
      summary: `\`go env\` persistently changes ${name}`,
    });
  }

  return operations;
}

/** Prefix assignments such as `GOSUMDB=off go test ./...`. */
function analyzeAssignments(assignments: readonly ShellAssignment[]): GoOperation[] {
  const operations: GoOperation[] = [];
  for (const assignment of assignments) {
    const bypass = checksumBypass(assignment.name, assignment.value);
    if (bypass !== undefined) {
      operations.push({
        eventClass: "ChecksumBypass",
        classification: "THIRD_PARTY_MUTATION",
        artifact: assignment.name,
        summary: bypass,
        minimumDecision: "deny",
      });
    }
  }
  return operations;
}

/**
 * Analyze a raw shell command string for Go supply-chain operations.
 *
 * Conservative by construction: if the string mentions `go` but no `go`
 * command could be resolved, or if the shell could not be read faithfully,
 * the result is `UNKNOWN_RISK` rather than silence.
 */
export function analyzeCommand(command: string): GoAnalysis {
  const parsed = parseShell(command);
  const operations: GoOperation[] = [];
  const notes: string[] = [...parsed.notes];
  let sawGo = false;
  let capable = false;
  let writesManifests = false;

  for (const simple of parsed.commands) {
    // A checksum bypass counts wherever it is set, even on a non-Go command:
    // `GOSUMDB=off make build` is still a bypass.
    operations.push(...analyzeAssignments(simple.assignments));

    const head = simple.argv[0];
    if (head === undefined) continue;
    // `gofmt` must not match `go`; compare the whole final path segment.
    if (commandName(head.text) !== "go") continue;

    sawGo = true;
    const sub = simple.argv[1]?.text;
    const rest = simple.argv.slice(2);

    if (sub === undefined || INERT_SUBCOMMANDS.has(sub)) continue;

    if (MANIFEST_WRITING_SUBCOMMANDS.has(sub)) writesManifests = true;

    if (sub === "get") operations.push(...analyzeGet(rest));
    else if (sub === "install") operations.push(...analyzeInstall(rest));
    else if (sub === "run") operations.push(...analyzeRun(rest));
    else if (sub === "mod") operations.push(...analyzeMod(rest));
    else if (sub === "work") operations.push(...analyzeWork(rest));
    else if (sub === "env") operations.push(...analyzeEnv(rest));

    if (CAPABLE_SUBCOMMANDS.has(sub)) capable = true;
    else if (!INERT_SUBCOMMANDS.has(sub) && sub !== "get" && sub !== "mod" && sub !== "env") {
      // An unrecognized `go` subcommand can still fetch or execute.
      capable = true;
      notes.push(`unrecognized \`go ${sub}\` subcommand; treated conservatively`);
    }
  }

  // SAFETY NET: the parser is not a shell. If `go` appears as a bare word but
  // nothing resolved to a Go command, some wrapper was not modelled -- and
  // "found nothing" would be the wrong conclusion.
  const unresolved = hasUnresolvedCommandWord(parsed.commands, "go");
  if (parsed.opaque || unresolved) {
    if (unresolved) {
      notes.push(
        "a `go` word appears in an argument position, so a wrapper was not recognized",
      );
    }
    return {
      classification: "UNKNOWN_RISK",
      operations,
      notes,
      // An unreadable command is not a licence to rewrite manifests unnoticed.
      writesManifests: false,
    };
  }

  if (operations.length === 0) {
    return capable
      ? { classification: "THIRD_PARTY_CAPABLE", operations, notes, writesManifests }
      : { ...IRRELEVANT, notes, writesManifests };
  }

  const mutation = operations.some((op) => op.classification === "THIRD_PARTY_MUTATION");
  return {
    classification: mutation ? "THIRD_PARTY_MUTATION" : "THIRD_PARTY_CAPABLE",
    operations,
    notes,
    writesManifests,
  };
}
