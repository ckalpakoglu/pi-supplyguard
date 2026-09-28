# pi-supplyguard

A policy enforcement layer for AI coding agents that makes dependency, tooling,
build, and CI supply-chain trust decisions explicit, independently checked,
reviewable, and enforceable before execution.

> **Status: in development.** The Go pipeline is feature-complete and covered
> by tests, but this is pre-release software: the versioned milestones are
> done while npm/Python/Cargo adapters, Socket Firewall and publication are
> not. Configuration and behavior may still change without notice, the
> package is not on npm, and it has had one primary user and reviewer — treat
> it as an experiment to evaluate, not a finished control. Read
> [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) before relying on it, and pin a
> commit if you do.

`pi-supplyguard` is an extension for the [Pi coding agent](https://pi.dev). It
intercepts supply-chain-relevant agent tool calls **before** execution,
normalizes them into ecosystem-independent security events, evaluates local
policy, and returns one of four decisions:

```text
ALLOW < WARN < ASK < DENY      (the most restrictive decision wins)
```

`ASK` is a real human gate: the agent cannot approve its own trust decisions.
In a headless session an `ASK` fails closed.

- **Initial ecosystem:** Go / Go Modules (npm, Python and others are planned as
  adapters, without redesigning the policy engine).
- **Default profile:** `standard`.
- **License:** Apache-2.0.

## Contents

- [Why](#why)
- [What is enforced today](#what-is-enforced-today)
- [Installation](#installation) — Pi and omp
- [Security profiles](#security-profiles)
- [Configuration](#configuration)
- [Tools and commands](#tools-and-commands)
- [How a tool call is evaluated](#how-a-tool-call-is-evaluated)
- [Project layout](#project-layout)
- [Development](#development)
- [Documentation](#documentation)

## Why

An AI coding agent with shell access can add dependencies, install tools,
execute ephemeral packages, weaken checksum verification, or edit CI
configuration — accidentally or adversarially. `pi-supplyguard` moves those
decisions out of prompts and into executable, auditable policy. The threat
model in detail is [`docs/SPEC.md` §3](docs/SPEC.md); in summary, in-scope
threats include:

- unpinned and floating dependencies and tools, including `@latest`;
- compromised newly released package versions and dependency confusion;
- typosquatting and repository impersonation;
- integrity-control bypass such as `GOSUMDB=off`;
- direct and indirect mutation of `go.mod` / `go.sum`;
- mutable GitHub Actions references and `curl | sh` installer pipelines;
- delegated sub-agents repeating risky behavior (workers inherit the same
  enforcement and, being headless, cannot pass a human gate).

It is for anyone who runs an AI agent against a real codebase — particularly
Go projects today — and wants supply-chain changes to be explicit and
reviewable instead of silent.

## What is enforced today

**Honesty first:** `pi-supplyguard` is a security control, and a security
control that overstates its coverage is worse than none. This section
describes the present, not the roadmap. Milestones M1 (Pi skeleton: hook,
config, profiles, decisions, audit), M2 (Go command gate) and M3 (manifest
engine: snapshots, semantic `go.mod` state, vendor detection and drift) are
complete, as are M4 (dependency justification, release cooldown, scoped
one-shot overrides), M5 (identity protection), M6 (vulnerability metadata) and
M7 (Socket CLI scans), M8 (generic policies) and M9 (adversarial hardening).
Everything in
[`docs/SPEC.md`](docs/SPEC.md) beyond that is **not yet implemented**. [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) tracks each gap.

Enforced now:

- Every Pi tool call is classified (`SUPPLY_CHAIN_IRRELEVANT`,
  `THIRD_PARTY_CAPABLE`, `THIRD_PARTY_MUTATION`, `UNKNOWN_RISK`); harmless
  operations such as `ls` or `git status` are not blocked or flagged.
- **Go command gate** (shell-aware, not a prefix match): `go get`, `go
  install`, `go mod …`, `go env`, `go work` and third-party `go run
  module@version` are recognized through wrappers and composition such as
  `env FOO=x go get …`, `cd dir && go get …`, `sh -c 'go get …'` (including
  combined flags like `bash -lc`) and `command go get …`.
- **Directive execution:** `go generate` runs the `//go:generate` directives
  declared in source — arbitrary commands, vendored files included, and a
  classic shape is `//go:generate go run tool@latest`. It is gated as a
  third-party execution in every profile.
- **Exact versions:** a bare module path (`go get github.com/foo/bar`) and
  floating versions (`@latest`, `v1`, branch names) are denied; only an exact
- **Local content scan (M10):** a dependency heading for a human gate has its
  own source scanned — from `vendor/` or the module cache, offline, no
  provider — for import-time network calls and process execution,
  environment harvesting beside egress, encoded payload blobs, cgo `dlopen`
  and `//go:generate` directives inside the dependency. Findings reach the
  approval prompt as file:line the human can read. Honest limits: it is a
  heuristic for lazy/templated malware; when the source is not locally
  resolvable yet the prompt says so instead of looking clean. `go.sum` changes
  name which module moved, from and to which version.
- **Optional Jev analyzer:** an experimental second opinion over the same
  source, `jev.enabled` in configuration, **default off**, never a
  dependency — the local scan needs no key, and a high-confidence verdict
  contributes at most an ask while experimental.
- **Checksum integrity:** `GOSUMDB=off`, `GONOSUMDB`, `GOFLAGS=-insecure`,
  `GOINSECURE` and `GOPRIVATE=*` are denied in every profile. Checksum
  verification is never weakened to make a proxy or scanner work.
- Unreadable or unrecognized package/network-capable commands are treated as
  `UNKNOWN_RISK` and fail conservative (ask / ask / deny by profile), and the
  audit record says which trigger made them unreadable.
- **Manifest reconciliation:** the tracked files (`go.mod`, `go.sum`,
  `go.work`, `go.work.sum`, `vendor/modules.txt`) are snapshotted before every
  tool call and compared on the next one, so a change made by `sed`, a Python
  script or generated code becomes the same normalized event a `go get` would
  have produced — add, upgrade, downgrade, remove, replace, exclude. Deleting
  `go.sum` is a checksum bypass and is denied in every profile. A command a human
  approved and that is *supposed* to rewrite a manifest — and only such a
  command — is reconciled and audited instead of being asked about twice. Detection happens on the following tool
  call: Pi's hook runs before a tool executes, so the boundary is "the agent
  cannot keep working after an unapproved edit", not "the edit cannot happen".
  A command that can be *read* as writing a tracked manifest — a redirection,
  `sed -i`, `cp`/`mv`/`tee`, even `git checkout go.mod` — is gated **before** it
  runs, which closes the substitute-build-revert sequence that leaves no trace
  for a snapshot to find. A write into **vendored source** — `sed -i vendor/…`,
  `cp … vendor/…`, a redirection — is vendor drift and is gated before it runs;
  the tree enforced builds compile from is not something to hand-edit. And a
  tool call that runs with input differing from what SupplyGuard evaluated (a
  co-installed extension revising it after the gate) is warned about and
  audited.
- **Go vendor model:** an existing vendor tree is detected and, after a
  one-time question whose answer is persisted and audited, enforced —
  `vendor/modules.txt` that no longer matches `go.mod` is vendor drift (warn in
  `standard`, deny in `hardened`/`paranoid`). `paranoid` enforces vendoring
  without asking and denies dependency mutation in a project that has no vendor
  tree.
- **Dependency justification:** SupplyGuard registers an LLM-callable tool,
  `supplyguard_justify_dependency`. Before adding, upgrading or executing a
  third-party dependency the agent must record the exact module and version,
  what it is for, whether the standard library was considered and why it is
  insufficient (SPEC §11.2). An operation with no matching justification is
  denied and told to call the tool; a justified one is put to a human with the
  rationale shown next to the change. Recording a justification is **not**
  approval — it is evidence at the gate, and it covers one module at one
  version for one run.
- **Release cooldown:** a version published inside the cooldown window
  (10 days by default) warns in `standard` and is denied in `hardened` and
  `paranoid`, with a one-shot override a human can grant — and `paranoid`
  demands a written reason for it. The publication date comes from the Go
  module proxy, the only outbound request SupplyGuard makes; `GOPRIVATE`,
  `GONOPROXY` and `GOPROXY=off` are honored before a request is built, so a
  private module is never named to a public service. A proxy that cannot answer
  warns below `paranoid` and fails closed in it, with no override (SPEC §17.3).
- **Scoped overrides:** an override waives one denial, for one artifact at one
  version, for one execution, and is audited with its reason. Only the cooldown
  opts into being waivable — a floating version, a checksum bypass or a missing
  justification is never offered an override.
- **Installer pipelines:** `curl … | sh`, `wget … | bash` and the same shape
  piped into `python`, `node` or `perl` are denied in every profile — no
  override lifts them (SPEC §15.2). Grouping (`| (sh)`) does not hide the pipe.
  A download that is *not* executed is a different event, and piping fetched
  data into a local script is ordinary work that stays free.
- **GitHub Actions pinning:** `uses: actions/checkout@v4` is a mutable
  reference — the tag can be repointed at any commit. Introducing one asks in
  `standard` and is denied in `hardened` and `paranoid`; only a full
  40-character commit SHA counts as pinned. Workflow files are part of the
  manifest snapshot set, so a workflow rewritten by a script is caught the same
  way `go.mod` is.
- **Typo- and repository-squatting:** module identities are compared against a
  user-controlled corpus of *protected identities* — component by component
  (host / owner / repository), with a Damerau-Levenshtein distance that counts
  an adjacent transposition as one edit. The protected repository name under a
  different owner (`random-owner/uuid` for `google/uuid`) is a signal of its
  own, precisely because its edit distance is large. The profile widens the net
  (0.08 / 0.15 / 0.25); a match asks in `standard` and is denied with an
  override above it. **The corpus is not an allow-list**, and with no corpus the
  analysis is disabled rather than guessed — `paranoid` says so in the prompt.
- **Known vulnerabilities:** every artifact heading for a trust decision is
  checked against [OSV](https://osv.dev), which needs no account or token. A
  **critical** advisory is denied in every profile and cannot be overridden; a
  **high** one asks in `standard` and is denied with an override above it. An
  advisory whose severity the database does not state is treated as unresolved,
  not as mild — `paranoid` denies it (SPEC §16). Withdrawn advisories are
  ignored. `GOPRIVATE` applies here exactly as it does to the proxy: a private
  module name is never sent to a public database.
- **Socket artifact scans** (optional): when the [Socket CLI](https://socket.dev)
  is installed, every artifact heading for a trust decision is scored with
  `socket package score`. A **critical** alert denies in every profile; a high
  one asks below `paranoid` and denies in it. Socket is *additive* — a clean
  Socket result can never rescue a dependency the local checks refused
  (SPEC §13.5). `paranoid` requires a working Socket and denies without one;
  `hardened` warns and carries on. **Socket Firewall is not implemented** — see
  [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) §1.5, and note that
  `socket package score` needs a Socket API token.
- **Fail closed:** internal SupplyGuard errors block the call rather than
  passing it through, and a headless `ASK` is denied.
- **Audit:** supply-chain-relevant tool calls (harmless ones are not
  audited) and configuration notices are appended to a local JSONL audit log
  with profile, session, repository, branch, event and decision. Secrets and
  raw environment dumps are never recorded.

Not yet implemented: Socket Firewall and the Socket manifest scan, npm /
Python / Cargo adapters, brokering a delegated worker's `ASK` up to the Chief
UI, and defense against a hostile co-installed extension. Each is documented
with its reason in [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md).

## Installation

`pi-supplyguard` is a Pi package (`pi-package` keyword; the extension entry
point is declared in `package.json` under `pi.extensions`). It is **not
published to npm yet**; install it from a local checkout or a git source.

From a local checkout:

```bash
pi install /absolute/path/to/pi-supplyguard        # user settings
pi install -l ./relative/path/to/pi-supplyguard    # project settings
```

From git (pin a tag or commit ref; Pi clones it and runs npm install):

```bash
pi install git:github.com/ckalpakoglu/pi-supplyguard@<ref>
```

To try it once without installing:

```bash
pi -e git:github.com/ckalpakoglu/pi-supplyguard
```

Installed packages can be listed with `pi list` and enabled/disabled with
`pi config`. Pi packages run with full system access — review the source
before installing, as you should for any supply-chain tool.

omp (oh-my-pi) is supported from the same code: it reads the entry point from
`package.json` under `omp.extensions` (falling back to `pi.extensions`). To try
it once:

```bash
omp -e /absolute/path/to/pi-supplyguard/src/index.ts
```

omp-specific tool surfaces and what each one gets are listed in
[`docs/KNOWN-GAPS.md` §1.14](docs/KNOWN-GAPS.md).

Requirements: Node.js with native TypeScript type-stripping (the extension
ships as `.ts` and is loaded directly by Pi).

## Security profiles

Profiles are ordered `standard < hardened < paranoid`. The effective profile is
the maximum of the global and project profile; a project may tighten the
global baseline but may never silently weaken it (weakening attempts are
ignored, warned about and audited).

`standard` is security-conscious development with low friction; `hardened`
raises gates for production/security-sensitive work; `paranoid` treats
dependency compromise as an active threat.

Behavior that differs per profile **today** (from the enforced baseline
tables; the full design matrix is [`docs/SPEC.md` §4.4](docs/SPEC.md)):

| Behavior | standard | hardened | paranoid |
|---|---|---|---|
| Unversioned / `@latest` / floating Go dependency or tool op | Deny | Deny | Deny |
| Exact-version dependency add/upgrade/replace, tool install, third-party execution | Ask | Ask | Ask |
| The same, with no recorded justification | Deny | Deny | Deny |
| Artifact published inside the release cooldown | Warn + Ask | Deny + override | Deny + override with a written reason |
| Release date unavailable (proxy unreachable) | Warn | Warn | Deny, no override |
| `curl \| sh` / `wget \| bash` installer pipeline | Deny | Deny | Deny |
| Newly introduced mutable GitHub Actions reference | Ask | Deny | Deny |
| Resembles a protected identity / repository squat | Ask | Deny + override | Deny + override with a written reason |
| Known **critical** vulnerability | Deny, no override | Deny, no override | Deny, no override |
| Known **high** vulnerability | Ask | Deny + override | Deny + override with a written reason |
| Advisory with no stated severity | Ask | Ask | Deny + override with a written reason |
| Socket critical alert | Deny | Deny | Deny |
| Socket unavailable / unauthenticated | Warn | Warn | Deny |
| Network fetch that is not executed | Allow | Ask | Deny |
| Checksum-integrity bypass (`GOSUMDB=off`, …) | Deny | Deny | Deny |
| Build/test-shaped Go commands (`go build`, `go test`, …) | Allow | Allow | Warn |
| `go generate` (runs `//go:generate` directives from any source file) | Ask | Ask | Ask |
| Content-scan finding in dependency source (`ArtifactAnomaly`) | Ask | Ask | Ask |
| Dependency whose source is not locally resolvable yet | Ask + banner | Ask + banner | Ask + banner (build gated until scanned, M11) |
| Unreadable / unrecognized risky command (`UNKNOWN_RISK`) | Ask | Ask | Deny |
| Tracked manifest change nobody approved (`sed`, script, editor) | Ask | Ask | Ask |
| Existing Go vendor tree | Ask → enforce | Ask → enforce | Enforce |
| Vendor tree that no longer matches `go.mod` | Warn | Deny | Deny |
| Dependency mutation with no vendor tree | Allow | Allow | Deny |
| Harmless operations (`ls`, `git status`, `gofmt`, reading files) | Allow | Allow | Allow |

## Configuration

```text
Global policy            ~/.config/pi-supplyguard/config.yaml
Project policy           <repo>/.supplyguard.yaml
Global trust corpus      ~/.config/pi-supplyguard/trust.yaml
Project trust corpus     <repo>/.supplyguard-trust.yaml
Remembered state         ~/.local/state/pi-supplyguard/state.json
Audit log                ~/.local/state/pi-supplyguard/audit.jsonl
```

`XDG_CONFIG_HOME` and `XDG_STATE_HOME` are honored. Precedence:

```text
compiled safe minimums
→ global configuration
→ project configuration
→ scoped runtime decision
```

Each layer may only tighten the previous one. Configuration currently supports
`profile`, `releaseAge.minimumDays`, `audit.enabled` and
`socket.enabled` (`off` / `auto` / `required`); unknown keys are ignored with a warning rather than silently
accepted. Project configuration is re-read within a few seconds of change.

Example:

```yaml
version: 1
profile: hardened
audit:
  enabled: true
```

## Tools and commands

The extension registers one LLM-callable tool:

- `supplyguard_justify_dependency` — the agent records why a dependency is
  needed (module, exact version, purpose, whether stdlib was considered and why
  it is insufficient) before the operation that takes it on. Unjustified
  dependency operations are denied.

and two commands:

- `/supplyguard-status` — show the effective profile, configuration sources
  and their statuses, registered ecosystem adapters, the cooldown setting, the
  watched manifest files and whether a baseline exists, per-ecosystem state
  (Go project and vendor state), remembered project decisions, audit/state
  paths and the current enforcement state.
- `/supplyguard-profile` — show the effective profile, or tighten it for the
  current session only (`/supplyguard-profile paranoid`). It can never lower
  the effective profile and never writes configuration files; lowering the
  profile is a deliberate, reviewable configuration edit.

## How a tool call is evaluated

```text
Pi tool_call
→ snapshot the tracked manifests, and reconcile the previous call's changes
→ classification (every call)
→ ecosystem adapter (Go today) → normalized supply-chain events, from the
  command AND from any manifest change nobody approved
→ project state (vendor model), once its ask-once questions are answered
→ profile baseline + findings (most restrictive wins)
→ ASK prompts the human (headless: deny)
→ DENY blocks before execution
→ audit
```

## Project layout

```text
src/index.ts        host wiring: hooks, approval UI, audit, commands, tool
src/host/           host tool shapes normalized for the core (omp, Pi)
src/core/           policy engine: events, decisions, profiles, manifest
                    snapshots, approval, justification, config, audit, state
src/adapters/       ecosystem adapters (Go today) behind a registry
src/generic/        ecosystem-agnostic policy: shell parsing, installer
                    pipelines, sensitive writes, GitHub Actions references
src/analyzers/      identity analysis (Damerau-Levenshtein, squatting)
src/providers/      external providers (Socket CLI)
types/              hand-written declarations for the host extension API
test/               the suite every rule above is pinned by
docs/               SPEC.md (canonical design), KNOWN-GAPS.md (honesty)
```

The policy core is ecosystem-agnostic: Go knowledge lives only in its adapter,
and there is no hard-coded command branch in the engine. New ecosystems are
added as event producers/verifiers without redesigning it.

## Development

```bash
npm run check     # typecheck (tsc --noEmit) + tests (node --test)
```

The test suite uses Node's built-in test runner — no test framework
dependency. Tests include Go command parsing, shell wrapper/bypass cases,
semantic `go.mod`/`go.sum` diffing, manifest snapshots and end-to-end
`sed`/script reconciliation through the real runtime, vendor drift, profile
decision contract tables, configuration precedence, audit redaction and
mutation checks on the wiring layer.

**Dependency policy:** the runtime has a single pinned dependency
(`yaml@2.9.0`, zero transitive dependencies) plus Node built-ins; dev
dependencies are exact-pinned `typescript` and `@types/node`. No floating
versions (`^`, `~`, `@latest`) are used in `dependencies`/`devDependencies`
(the optional host peerDependency is deliberately `*` pending compatibility
testing — see KNOWN-GAPS §1.9), and no dependency is added or
upgraded without explicit human review. A supply-chain tool should not have a
supply-chain problem.

## Documentation

- [`docs/SPEC.md`](docs/SPEC.md) — canonical product and security design.
- [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) — what is not enforced yet,
  deliberate decisions, and the defect log.
- [`SECURITY.md`](SECURITY.md) — security policy and scope.

## License

[Apache-2.0](LICENSE)
