# pi-supplyguard

A policy enforcement layer for AI coding agents that makes dependency, tooling,
build and CI supply-chain trust decisions explicit, independently checked,
reviewable, and enforceable before execution.

> **Status: in development.** Go and npm are feature-complete and tested, but
> this is pre-release software: Python/Cargo adapters, Socket Firewall and
> publication are not done, behavior may change without notice, and it has had
> one primary user and reviewer. Read [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md)
> before relying on it, and pin a commit if you do.

`pi-supplyguard` is an extension for the [Pi coding agent](https://pi.dev). It
intercepts supply-chain-relevant tool calls **before** execution, normalizes
them into ecosystem-independent events, evaluates local policy, and returns one
of four decisions:

```text
ALLOW < WARN < ASK < DENY      (the most restrictive decision wins)
```

`ASK` is a real human gate — the agent cannot approve its own trust decisions.
In a headless session an `ASK` fails closed.

- **Ecosystems today:** Go / Go Modules and npm (Python, Cargo and others are
  planned as adapters, without redesigning the policy engine).
- **Default profile:** `standard`.
- **License:** Apache-2.0.

## Why

An AI coding agent with shell access can add dependencies, install tools,
execute ephemeral packages, weaken checksum verification, or edit CI
configuration — accidentally or adversarially. `pi-supplyguard` moves those
decisions out of prompts and into executable, auditable policy. The full
threat model is [`docs/SPEC.md` §3](docs/SPEC.md); in summary:

- unpinned and floating dependencies and tools, including `@latest`;
- compromised new releases and dependency confusion;
- typosquatting and repository impersonation;
- integrity-control bypass such as `GOSUMDB=off`;
- direct and indirect mutation of dependency manifests;
- mutable GitHub Actions references and `curl | sh` installer pipelines;
- delegated sub-agents repeating risky behavior (workers inherit the same
  enforcement and, being headless, cannot pass a human gate).

## What is enforced today

**Honesty first:** this section describes the present, not the roadmap.
Milestones M1–M9 plus the zero-day hardening line M10–M14 are complete —
Pi skeleton, the Go command gate, the manifest engine, the human trust gate,
identity protection, OSV, Socket scans, generic policies, adversarial
hardening, local content evidence, hermetic builds and vendor quarantine,
bypass closure, the npm adapter, and freshness (replay corpus, live contract
tests, homoglyphs, corpus tooling, optional repository signals). Everything in
[`docs/SPEC.md`](docs/SPEC.md) beyond that is **not yet implemented**;
[`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) tracks each gap.

Enforced now:

- **Classification:** every tool call is classified (`SUPPLY_CHAIN_IRRELEVANT`,
  `THIRD_PARTY_CAPABLE`, `THIRD_PARTY_MUTATION`, `UNKNOWN_RISK`); harmless
  operations such as `ls` or `git status` are neither blocked nor flagged.
  Unreadable or unrecognized risky commands are `UNKNOWN_RISK` and fail
  conservative (ask / ask / deny by profile).
- **Go command gate** (shell-aware, never a prefix match): `go get`,
  `go install`, `go mod …`, `go env`, `go work` and third-party
  `go run module@version` are recognized through wrappers and composition —
  `env FOO=x go get …`, `cd dir && go get …`, `sh -c 'go get …'`, combined
  flags like `bash -lc`, `command go get …`. `go generate` is gated as a
  third-party execution in every profile: it runs the `//go:generate`
  directives declared in any source file, vendored files included.
- **Exact versions:** a bare module path and floating versions (`@latest`,
  `v1`, branch names) are denied; only an exact semantic version or full
  commit hash proceeds to the trust pipeline (an `ASK` requiring human
  approval).
- **Checksum integrity:** `GOSUMDB=off`, `GONOSUMDB`, `GOFLAGS=-insecure`,
  `GOINSECURE` and `GOPRIVATE=*` are denied in every profile, and so is a
  scoped `GOPRIVATE`/`GONOSUMDB` that happens to cover the very module being
  added. Checksum verification is never weakened to make a proxy or scanner
  work.
- **npm:** `npm|pnpm|yarn|bun` installs, adds, removals, global installs and
  `npx` fetch-and-run are gated through the same shell-aware parser. The
  threat model is the lifecycle script: every dependency the lockfile marks
  `hasInstallScript` is reported, with its script body read from
  `node_modules` and shown in the approval prompt. `package.json` and
  `package-lock.json` changes are semantic — both lockfile layouts (legacy
  flat and `packages[]`, lockfileVersion 2/3), version swaps named
  `from→to`. Ranges (`^1.2.3`) stay usable; bare names and dist-tags
  (`latest`, `next`) carry the floating-version deny floor.
- **Manifest reconciliation:** tracked files (`go.mod`, `go.sum`, `go.work`,
  `go.work.sum`, `vendor/modules.txt`, `package.json`, `package-lock.json`,
  `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`) are snapshotted
  before every tool call and compared on the next one, so a change made by
  `sed`, a Python script or generated code becomes the same normalized event
  a `go get` would have produced — add, upgrade, downgrade, remove, replace,
  exclude. Deleting `go.sum` is a checksum bypass, denied in every profile.
  A command a human approved that is *supposed* to rewrite a manifest — and
  only such a command — is reconciled and audited instead of asked about
  twice. Detection happens on the following tool call: Pi's hook runs before
  a tool executes, so the boundary is "the agent cannot keep working after an
  unapproved edit", not "the edit cannot happen".
- **Writes gated before they land:** a command that can be *read* as writing a
  tracked manifest — a redirection, `sed -i`, `cp`/`mv`/`tee`, even
  `git checkout go.mod` — is gated **before** it runs, closing the
  substitute-build-revert sequence that leaves no trace for a snapshot. The
  same guard covers **file tools** (`edit`, `write`, …) and vendored trees:
  writing into `vendor/` or `node_modules/` — by shell command or file tool,
  relative or absolute path — is vendor drift, gated before it runs; the
  tree enforced builds compile from is not something to hand-edit, and
  nothing snapshots it later.
- **Go vendor model:** an existing vendor tree is detected and, after a
  one-time persisted, audited question, enforced — `vendor/modules.txt` that
  no longer matches `go.mod` is vendor drift. `paranoid` enforces vendoring
  without asking and denies dependency mutation in a project with no vendor
  tree.
- **Dependency justification:** the agent-facing tool
  `supplyguard_justify_dependency` must record the exact module and version,
  purpose, and why the standard library is insufficient (SPEC §11.2) before
  adding, upgrading or executing a third-party dependency. No matching
  justification → denied; justified → put to a human with the rationale shown
  next to the change. Recording a justification is **not** approval, and it
  covers one module at one version for one run.
- **Release cooldown:** a version published inside the cooldown window
  (10 days default) warns in `standard`, denies with a one-shot override in
  `hardened`/`paranoid` (`paranoid` demands a written reason). Dates come
  from the Go module proxy — the only outbound request SupplyGuard makes;
  `GOPRIVATE`, `GONOPROXY` and `GOPROXY=off` are honored before a request is
  built, so a private module is never named to a public service. A proxy that
  cannot answer warns below `paranoid` and fails closed in it (SPEC §17.3).
- **Scoped overrides:** an override waives one denial, for one artifact at one
  version, for one execution, audited with its reason. Only the cooldown opts
  into being waivable — a floating version, a checksum bypass or a missing
  justification is never offered one.
- **Installer pipelines:** `curl … | sh`, `wget … | bash` and the same shape
  piped into `python`, `node` or `perl` are denied in every profile, with no
  override. Grouping (`| (sh)`) does not hide the pipe, and neither does
  splitting it: executing a file this session downloaded —
  `curl -o x.sh …; sh x.sh`, in one command or a later call — is the same
  denial. A download that is only *read* stays free; that is the honest
  escape.
- **GitHub Actions pinning:** a mutable reference — `uses: actions/checkout@v4`
  or an unpinned `docker://alpine:3` tag — asks in `standard` and is denied in
  `hardened`/`paranoid`; only a 40-character commit SHA
  (`docker://image@sha256:<64 hex>` for images) counts as pinned. Workflow
  files are part of the manifest snapshot set.
- **Typo- and repository-squatting:** module identities are compared against a
  user-controlled corpus of *protected identities* — component by component
  (host / owner / repository), with Damerau-Levenshtein distance counting an
  adjacent transposition as one edit, and confusable characters (Cyrillic `о`,
  Greek `ν`) folded onto their Latin lookalikes first. The protected
  repository name under a different owner is a signal of its own, precisely
  because its edit distance is large. The profile widens the net
  (0.08 / 0.15 / 0.25). **The corpus is not an allow-list** —
  `/supplyguard-trust init` seeds one from `go.mod` — and with no corpus the
  analysis is disabled rather than guessed, which `paranoid` says in the
  prompt.
- **Known vulnerabilities:** every artifact heading for a trust decision is
  checked against [OSV](https://osv.dev) (no account or token). **Critical**
  advisories deny in every profile and cannot be overridden; **high** asks in
  `standard`, denies with an override above it. An advisory with no stated
  severity is treated as unresolved, not mild — `paranoid` denies it
  (SPEC §16). Withdrawn advisories are ignored; `GOPRIVATE` applies exactly
  as it does to the proxy.
- **Local content scan:** a dependency heading for a human gate has its own
  source scanned — from `vendor/` or the module cache, offline — for
  import-time network calls and process execution, environment harvesting,
  encoded payload blobs, cgo `dlopen` and `//go:generate` directives inside
  the dependency. Findings reach the approval prompt as file:line. It is a
  heuristic for lazy/templated malware; when the source is not locally
  resolvable yet, the prompt says so instead of looking clean. An optional
  second opinion (`jev.enabled`, default off, never a dependency, no key
  needed for the local scan) contributes at most an ask while experimental.
- **Socket artifact scans** (optional): with the [Socket CLI](https://socket.dev)
  installed, every artifact heading for a trust decision is scored with
  `socket package score`. A **critical** alert denies in every profile; a
  high one asks below `paranoid` and denies in it. Socket is *additive* — a
  clean result can never rescue a dependency the local checks refused
  (SPEC §13.5). `paranoid` requires a working Socket and denies without one;
  `hardened` warns and carries on. Socket **Firewall** is not implemented
  (KNOWN-GAPS §1.5); `socket package score` needs a Socket API token.
- **Fail closed:** internal SupplyGuard errors block the call rather than
  passing it through; a headless `ASK` is denied. A tracked file that changes
  while no tool call is executing, or a tool call that runs with input
  differing from what SupplyGuard evaluated (a co-installed extension
  revising it after the gate), is reported and audited.
- **Audit:** supply-chain-relevant tool calls (harmless ones are not audited)
  and configuration notices are appended to a local JSONL audit log with
  profile, session, repository, branch, event and decision. Secrets and raw
  environment dumps are never recorded.

Not yet implemented: Socket Firewall and the Socket manifest scan, Python and
Cargo adapters, release-age/OSV/content evidence for npm artifacts (their
evidence today is lifecycle scripts and lockfile metadata), brokering a
delegated worker's `ASK` up to the Chief UI, and *preventing* a hostile
co-installed extension from revising approved input (detected and audited, not
prevented). Each is documented with its reason in
[`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md).

## Installation

`pi-supplyguard` is a Pi package (`pi-package` keyword; the entry point is
declared in `package.json` under `pi.extensions`). It is **not published to
npm yet**; install it from a local checkout or a git source.

```bash
pi install /absolute/path/to/pi-supplyguard        # user settings
pi install -l ./relative/path/to/pi-supplyguard    # project settings
pi install git:github.com/ckalpakoglu/pi-supplyguard@<ref>   # pinned git ref
pi -e git:github.com/ckalpakoglu/pi-supplyguard              # try once
```

Installed packages are listed with `pi list` and toggled with `pi config`. Pi
packages run with full system access — review the source before installing, as
you should for any supply-chain tool.

omp (oh-my-pi) is supported from the same code (`omp.extensions`, falling back
to `pi.extensions`):

```bash
omp -e /absolute/path/to/pi-supplyguard/src/index.ts
```

omp-specific surfaces are listed in
[`docs/KNOWN-GAPS.md` §1.14](docs/KNOWN-GAPS.md).

Requirements: Node.js with native TypeScript type-stripping (the extension
ships as `.ts` and is loaded directly).

## Security profiles

Profiles are ordered `standard < hardened < paranoid`. The effective profile is
the maximum of the global and project profile; a project may tighten the global
baseline but may never silently weaken it (weakening attempts are ignored,
warned about and audited).

`standard` is security-conscious development with low friction; `hardened`
raises gates for production/security-sensitive work; `paranoid` treats
dependency compromise as an active threat.

Behavior that differs per profile **today** (from the enforced baseline tables;
the full design matrix is [`docs/SPEC.md` §4.4](docs/SPEC.md)):

| Behavior | standard | hardened | paranoid |
|---|---|---|---|
| Harmless operations (`ls`, `git status`, `gofmt`, reading files) | Allow | Allow | Allow |
| Unversioned / `@latest` / floating dependency or tool op | Deny | Deny | Deny |
| Exact-version dependency add/upgrade/replace, tool install, third-party execution | Ask | Ask | Ask |
| The same, with no recorded justification | Deny | Deny | Deny |
| Artifact published inside the release cooldown | Warn + Ask | Deny + override | Deny + override, written reason |
| Release date unavailable (proxy unreachable) | Warn | Warn | Deny, no override |
| `curl \| sh` / `wget \| bash` installer pipeline | Deny | Deny | Deny |
| Download executed one step later (`curl -o x.sh …; sh x.sh`) | Deny | Deny | Deny |
| Checksum-integrity bypass (`GOSUMDB=off`, …) | Deny | Deny | Deny |
| `GOPRIVATE` scope covering the module being added | Deny | Deny | Deny |
| Unreadable / unrecognized risky command (`UNKNOWN_RISK`) | Ask | Ask | Deny |
| `go generate` (runs `//go:generate` directives from any source) | Ask | Ask | Ask |
| Build/test-shaped Go commands (`go build`, `go test`, …) | Allow | Allow | Warn |
| `-mod=mod` build with a vendor tree present | Deny | Deny | Deny |
| Vendor tree that no longer matches `go.mod` | Warn | Deny | Deny |
| Dependency mutation with no vendor tree | Allow | Allow | Deny |
| Dependency whose source is not locally resolvable yet | Ask + banner | Ask + banner | Ask + banner (build gated until scanned) |
| Content-scan finding in dependency source | Ask | Ask | Ask |
| Known **critical** vulnerability | Deny, no override | Deny, no override | Deny, no override |
| Known **high** vulnerability | Ask | Deny + override | Deny + override |
| Advisory with no stated severity | Ask | Ask | Deny + override |
| Socket critical alert | Deny | Deny | Deny |
| Socket unavailable / unauthenticated | Warn | Warn | Deny |
| Resembles a protected identity / repository squat | Ask | Deny + override | Deny + override, written reason |
| Newly introduced mutable GitHub Actions reference or `docker://` tag | Ask | Deny | Deny |
| Network fetch that is not executed | Allow | Ask | Deny |
| npm dependency add, exact or range spec | Ask | Ask | Ask |
| npm add with bare name / `*` / `latest` / `next` | Deny | Deny | Deny |
| npm dependency running an install script (`postinstall`, …) | Ask, script body shown | Ask, script body shown | Ask, script body shown |
| `npx pkg@ver` fetch-and-run | Ask | Ask | Ask |
| Jev verdict (optional, `jev.enabled`) | — / Ask | — / Ask | — / Ask |
| Repository signal (optional, `signals.enabled`) | — / Ask | — / Ask | — / Ask |

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

Each layer may only tighten the previous one. Supported keys today: `profile`,
`releaseAge.minimumDays`, `audit.enabled`, `socket.enabled`
(`off` / `auto` / `required`), `jev.enabled`, `signals.enabled` (both default
off); unknown keys are ignored with a warning rather than silently accepted.
Project configuration is re-read within a few seconds of change.

The optional analyzers read credentials from the environment, never from
configuration files: `TYPESAFE_API_KEY` (or `JEV_API_KEY`) for Jev,
`GITHUB_TOKEN` for repository signals. Modules covered by
`GOPRIVATE`/`GONOPROXY`/`GOPROXY=off` are never sent to any of them.

```yaml
version: 1
profile: hardened
audit:
  enabled: true
```

## Tools and commands

One LLM-callable tool:

- `supplyguard_justify_dependency` — the agent records why a dependency is
  needed (module, exact version, purpose, stdlib considered, why it is
  insufficient) before the operation that takes it on. Unjustified dependency
  operations are denied.

Four commands:

- `/supplyguard-status` — effective profile, configuration sources, registered
  adapters, watched manifests, per-ecosystem state, remembered project
  decisions, and audit/state paths.
- `/supplyguard-profile` — show the effective profile, or tighten it for this
  session only (`/supplyguard-profile paranoid`). It can never lower the
  effective profile and never writes configuration files.
- `/supplyguard-trust init` — seed `.supplyguard-trust.yaml` from the
  repository's own `go.mod`, so typo- and repository-squatting analysis has a
  corpus without hand-writing one. Never overwrites an existing corpus.
- `/supplyguard-log [n]` — the last `n` audit records (default 20) in a
  scrollable popup: what was asked, decided and approved, newest last.

## How a tool call is evaluated

```text
Pi tool_call
→ snapshot the tracked manifests, and reconcile the previous call's changes
→ classification (every call)
→ ecosystem adapter (Go, npm today) → normalized supply-chain events, from the
  command AND from any manifest change nobody approved
→ project state (vendor model), once its ask-once questions are answered
→ local content scan of every artifact heading for a trust decision
→ profile baseline + findings, local and external (most restrictive wins)
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
src/adapters/       ecosystem adapters (Go, npm) behind a registry
src/generic/        ecosystem-agnostic policy: shell parsing, installer
                    pipelines, sensitive writes, GitHub Actions references
src/analyzers/      identity analysis and the local content scanner
src/providers/      external providers (Socket CLI, optional Jev and signals)
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

The suite (468 tests, Node's built-in runner, no test framework dependency)
includes Go and npm command parsing, shell wrapper/bypass cases, semantic
`go.mod`/`go.sum`/lockfile diffing (both npm lockfile layouts), manifest
snapshots and end-to-end `sed`/script reconciliation through the real runtime,
vendor drift and quarantine, profile decision contract tables, configuration
precedence, audit redaction, mutation checks on the wiring layer, and an
**incident replay corpus** — event-stream, node-ipc, ua-parser-js, the
`go generate` install shape and a Cyrillic typosquat replayed end-to-end; a
replay passing silently fails the build.

`test/live/live.test.ts` is the suite's only network-touching exception: real
Go proxy, real OSV, real Socket CLI, run with `LIVE=1` by the weekly CI job
(`.github/workflows/`) — the structural answer to a defect class where every
other test injected its runner and the live path had silently broken.

**Dependency policy:** the runtime has a single pinned dependency
(`yaml@2.9.0`, zero transitive dependencies) plus Node built-ins; dev
dependencies are exact-pinned `typescript` and `@types/node`. No floating
versions (`^`, `~`, `@latest`) are used in `dependencies`/`devDependencies`
(the optional host peerDependency is deliberately `*` pending compatibility
testing — see KNOWN-GAPS §4), and no dependency is added or upgraded without
explicit human review. A supply-chain tool should not have a supply-chain
problem.

## Documentation

- [`docs/SPEC.md`](docs/SPEC.md) — canonical product and security design.
- [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) — what is not enforced yet,
  deliberate decisions, and the defect log.
- [`SECURITY.md`](SECURITY.md) — security policy and scope.

## License

[Apache-2.0](LICENSE)
