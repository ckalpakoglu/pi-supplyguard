# pi-supplyguard

A policy enforcement layer for AI coding agents that makes dependency, tooling,
build, and CI supply-chain trust decisions explicit, independently checked,
reviewable, and enforceable before execution.

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

## Why

An AI coding agent with shell access can add dependencies, install tools,
execute ephemeral packages, weaken checksum verification, or edit CI
configuration — accidentally or adversarially. `pi-supplyguard` moves those
decisions out of prompts and into executable, auditable policy. The threat
model in detail is [`docs/SPEC.md` §3](docs/SPEC.md); in summary, in-scope
threats include:

- unpinned and floating dependencies and tools, including `@latest`;
- compromised newly released package versions and dependency confusion;
- typosquatting and repository impersonation *(planned, see
  [coverage](#what-is-enforced-today))*;
- integrity-control bypass such as `GOSUMDB=off`;
- direct and indirect mutation of `go.mod` / `go.sum` *(command gate only
  today, see [coverage](#what-is-enforced-today))*;
- mutable GitHub Actions references and `curl | sh` installer pipelines
  *(planned)*;
- delegated sub-agents repeating risky behavior (workers inherit the same
  enforcement and, being headless, cannot pass a human gate).

It is for anyone who runs an AI agent against a real codebase — particularly
Go projects today — and wants supply-chain changes to be explicit and
reviewable instead of silent.

## What is enforced today

**Honesty first:** `pi-supplyguard` is a security control, and a security
control that overstates its coverage is worse than none. This section
describes the present, not the roadmap. Milestones M1 (Pi skeleton: hook,
config, profiles, decisions, audit) and M2 (Go command gate) are complete.
Everything in [`docs/SPEC.md`](docs/SPEC.md) beyond that is **not yet
implemented**. [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) tracks each gap.

Enforced now:

- Every Pi tool call is classified (`SUPPLY_CHAIN_IRRELEVANT`,
  `THIRD_PARTY_CAPABLE`, `THIRD_PARTY_MUTATION`, `UNKNOWN_RISK`); harmless
  operations such as `ls` or `git status` are not blocked or flagged.
- **Go command gate** (shell-aware, not a prefix match): `go get`, `go
  install`, `go mod …`, `go env`, `go work` and third-party `go run
  module@version` are recognized through wrappers and composition such as
  `env FOO=x go get …`, `cd dir && go get …`, `sh -c 'go get …'` (including
  combined flags like `bash -lc`) and `command go get …`.
- **Exact versions:** a bare module path (`go get github.com/foo/bar`) and
  floating versions (`@latest`, `v1`, branch names) are denied; only an exact
  semantic version or full commit hash proceeds to the trust pipeline (an
  `ASK` requiring human approval).
- **Checksum integrity:** `GOSUMDB=off`, `GONOSUMDB`, `GOFLAGS=-insecure`,
  `GOINSECURE` and `GOPRIVATE=*` are denied in every profile. Checksum
  verification is never weakened to make a proxy or scanner work.
- Unreadable or unrecognized package/network-capable commands are treated as
  `UNKNOWN_RISK` and fail conservative (ask / ask / deny by profile).
- **Fail closed:** internal SupplyGuard errors block the call rather than
  passing it through, and a headless `ASK` is denied.
- **Audit:** supply-chain-relevant tool calls (harmless ones are not
  audited) and configuration notices are appended to a local JSONL audit log
  with profile, session, repository, branch, event and decision. Secrets and
  raw environment dumps are never recorded.

Not yet implemented (planned milestones M3–M9):

- manifest reconciliation — indirect `go.mod`/`go.sum` mutation via `sed`,
  scripts or generated code is **not detected today**;
- Go vendor state detection and drift enforcement (M3);
- dependency justification, scoped one-shot overrides, release-age cooldown
  (M4) — `releaseAge.minimumDays` is parsed but not yet consumed;
- typosquatting / repository-squatting analysis with a trust corpus (M5);
- vulnerability metadata, e.g. OSV (M6);
- Socket scans and Socket Firewall (M7);
- generic policies: GitHub Actions SHA pinning and `curl | sh` / `wget | sh`
  denial (M8);
- adversarial hardening against bypasses such as hostile co-installed
  extensions (M9).

Until those land, treat the command gate as one control among several, not an
admission boundary.

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
pi install git:github.com/<owner>/pi-supplyguard@<ref>
```

To try it once without installing:

```bash
pi -e git:github.com/<owner>/pi-supplyguard
```

Installed packages can be listed with `pi list` and enabled/disabled with
`pi config`. Pi packages run with full system access — review the source
before installing, as you should for any supply-chain tool.

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
tables; the full design matrix in [`docs/SPEC.md` §4.4](docs/SPEC.md) —
vendoring, release age, Socket, CI pinning — is enforced as those milestones
land):

| Behavior | standard | hardened | paranoid |
|---|---|---|---|
| Unversioned / `@latest` / floating Go dependency or tool op | Deny | Deny | Deny |
| Exact-version dependency add/upgrade/replace, tool install, third-party execution | Ask | Ask | Ask |
| Checksum-integrity bypass (`GOSUMDB=off`, …) | Deny | Deny | Deny |
| Build/test-shaped Go commands (`go build`, `go test`, …) | Allow | Allow | Warn |
| Unreadable / unrecognized risky command (`UNKNOWN_RISK`) | Ask | Ask | Deny |
| Harmless operations (`ls`, `git status`, `gofmt`, reading files) | Allow | Allow | Allow |

## Configuration

```text
Global policy            ~/.config/pi-supplyguard/config.yaml
Project policy           <repo>/.supplyguard.yaml
Global trust corpus      ~/.config/pi-supplyguard/trust.yaml        (M5)
Project trust corpus     <repo>/.supplyguard-trust.yaml            (M5)
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
`profile`, `releaseAge.minimumDays` (carried for M4, not yet consumed) and
`audit.enabled`; unknown keys are ignored with a warning rather than silently
accepted. Project configuration is re-read within a few seconds of change.

Example:

```yaml
version: 1
profile: hardened
audit:
  enabled: true
```

## Commands

- `/supplyguard-status` — show the effective profile, configuration sources
  and their statuses, registered ecosystem adapters, the cooldown setting,
  audit/state paths and the current enforcement state.
- `/supplyguard-profile` — show the effective profile, or tighten it for the
  current session only (`/supplyguard-profile paranoid`). It can never lower
  the effective profile and never writes configuration files; lowering the
  profile is a deliberate, reviewable configuration edit.

## How a tool call is evaluated

```text
Pi tool_call
→ classification (every call)
→ ecosystem adapter (Go today) → normalized supply-chain events
→ profile baseline + findings (most restrictive wins)
→ ASK prompts the human (headless: deny)
→ DENY blocks before execution
→ audit
```

## Development

```bash
npm run check     # typecheck (tsc --noEmit) + tests (node --test)
```

The test suite uses Node's built-in test runner — no test framework
dependency. Tests include Go command parsing, shell wrapper/bypass cases,
profile decision contract tables, configuration precedence, audit redaction
and mutation checks on the wiring layer.

**Dependency policy:** the runtime has a single pinned dependency
(`yaml@2.9.0`, zero transitive dependencies) plus Node built-ins; dev
dependencies are exact-pinned `typescript` and `@types/node`. No floating
versions (`^`, `~`, `@latest`) are used, and no dependency is added or
upgraded without explicit human review. A supply-chain tool should not have a
supply-chain problem.

## Documentation

- [`docs/SPEC.md`](docs/SPEC.md) — canonical product and security design.
- [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) — what is not enforced yet,
  deliberate decisions, and the defect log.
- [`SECURITY.md`](SECURITY.md) — security policy and scope.

## License

[Apache-2.0](LICENSE)
