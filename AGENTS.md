# AGENTS.md

## Repository

- Project: `pi-supplyguard`
- Working path: `/home/cx/code/pi-suppylyguard`
- Target: Pi Coding Agent extension
- Initial ecosystem: Go / Go Modules
- Future ecosystems: npm/Node.js, Python, Cargo, and others through adapters
- Default security profile: `standard`

## Mission

Build `pi-supplyguard` as a publishable supply-chain policy enforcement layer for Pi coding agents.

The product must make dependency, tooling, build, and CI supply-chain trust decisions:

- explicit;
- reviewable;
- enforceable before execution where Pi provides a pre-execution interception point;
- independently checked;
- auditable.

The canonical product and security design is `docs/SPEC.md`.

When implementation choices are ambiguous, follow `docs/SPEC.md` rather than inventing new behavior.

## Development Model

Use the configured Chief / side-agent workflow.

The Chief should primarily:

- understand the objective and current repository state;
- decompose substantial work;
- delegate implementation, exploration, testing, and security review where useful;
- inspect actual diffs and test output;
- protect Chief context from unnecessary implementation detail;
- integrate only after explicit human approval.

For every mutating worker:

```text
ONE AGENT
=
ONE BRANCH
=
ONE WORKTREE
=
ONE PI SESSION
=
ONE TMUX WINDOW
```

Read-only scouts and reviewers may be lighter-weight if they do not mutate repository state.

Never merge a worker into `main` without explicit human approval.

## Required Worker Handoff

Every mutating worker should return:

```text
DONE
- ...

DISCOVERED
- ...

RISKS
- ...

DEPENDENCY CHANGES
- none / details

SECURITY
- ...

TESTS
- ...

COMMITS
- ...
```

The Chief must verify the code, diff, and tests independently rather than trusting the handoff summary.

## Source-of-Truth Hierarchy

Use this order:

1. `docs/SPEC.md`
2. repository code and tests
3. explicit human decisions
4. durable project memory
5. worker summaries

Git and the filesystem are the source of truth for code state.

Memory is continuity/navigation, not proof that work was completed.

## Core Security Invariants

These are implementation constraints, not optional guidance.

1. The policy core is ecosystem-agnostic.
2. Go is the first production adapter.
3. `standard` is the default profile.
4. Profile ordering is:

   ```text
   standard < hardened < paranoid
   ```

5. Effective profile is:

   ```text
   effectiveProfile = max(globalProfile, projectProfile)
   ```

6. A project may tighten the global baseline but may not silently weaken it.
7. Every Pi tool call is classified.
8. Supply-chain-relevant and third-party-capable operations are gated.
9. Harmless operations such as `ls`, `git status`, `gofmt`, or reading a README are not sent to remote security providers merely because SupplyGuard is installed.
10. Policy decisions are ordered:

    ```text
    ALLOW < WARN < ASK < DENY
    ```

11. The most restrictive decision wins.
12. External intelligence is additive and may never weaken a stricter local SupplyGuard decision.
13. The agent cannot approve its own trust decision.
14. Overrides are scoped, one-shot, and audited.
15. Delegated workers inherit the same effective global SupplyGuard baseline.
16. Missing trust data must never cause SupplyGuard to invent trusted identities or ownership.
17. Direct command interception is not sufficient; indirect manifest mutation must be detected through before/after state reconciliation.
18. SupplyGuard must never disable or weaken Go checksum verification to make a proxy, scanner, or firewall work.
19. Secrets must never be written into model context, audit records, worker handoffs, or logs.
20. SupplyGuard itself must minimize and pin its own dependencies.

## Decision Model

All checks return one of:

- `ALLOW`
- `WARN`
- `ASK`
- `DENY`

Rules:

- `ASK` requires a real human gate.
- `DENY` must block execution when enforcement is possible before tool execution.
- A clean Socket/OSV/provider result cannot convert a local `ASK` or `DENY` into `ALLOW`.
- Local policy always remains authoritative.

## Security Profiles

### standard

Security-conscious normal development with low friction.

Expected behavior:

- exact versions required for new dependency/tool trust decisions;
- `@latest` and floating versions denied;
- invariant violations denied;
- new dependency and upgrade decisions require human approval;
- existing vendor state is detected and may be enforced;
- no vendor tree means vendoring is optional;
- Socket artifact/manifest scans are optional/off by default;
- Socket Firewall is off by default.

### hardened

Production/security-sensitive development.

Expected behavior:

- local policy becomes stricter;
- warnings may become gates;
- existing repository controls are strongly enforced;
- Socket scans are optional/recommended when configured;
- Socket Firewall is ask-once per project;
- default interactive choice is Enable;
- user may explicitly Continue without Firewall;
- the choice is persisted and audited;
- local hardened policy remains active when Firewall is declined;
- headless mode does not silently enable Firewall.

### paranoid

Assume dependency compromise is an active threat.

Expected behavior:

- Go vendoring is mandatory;
- Socket artifact evaluation is mandatory for new or changed third-party artifacts;
- Socket manifest/project scan is mandatory after dependency graph mutation;
- Socket Firewall is mandatory for dependency fetches;
- provider health/auth/version must be valid for new trust decisions;
- provider timeout, quota failure, unavailable, unsupported, or unscanned results fail closed for new trust decisions;
- unchanged approved vendored code may continue to build/test offline;
- Socket unavailability is not a normal one-shot approval path.

## Architecture Rules

Keep these layers separate:

- Pi integration
- event classifier
- ecosystem adapter registry
- normalized event model
- policy engine
- configuration
- state
- approvals
- audit
- analyzers
- external providers
- generic policies

The policy engine must not contain hard-coded ecosystem command branches such as:

```ts
if (command.startsWith("go get")) { ... }
```

Go-specific behavior belongs in the Go adapter.

Future npm, Python, or Cargo support must be added as new event producers/verifiers without redesigning the policy engine.

## Canonical Event Classes

The normalized event model should cover at least:

- `DependencyAdd`
- `DependencyUpgrade`
- `DependencyDowngrade`
- `DependencyRemove`
- `DependencyReplace`
- `ToolInstall`
- `ToolUpgrade`
- `ThirdPartyExecution`
- `LockfileMutation`
- `VendorDrift`
- `ChecksumBypass`
- `RegistryAccess`
- `DependencyFetch`
- `CIReferenceAdd`
- `CIReferenceChange`
- `NetworkRequirement`
- `SecurityGateChange`
- `SecurityBypass`

## Tool-Call Classification

Every Pi tool call must be classified into one of:

- `SUPPLY_CHAIN_IRRELEVANT`
- `THIRD_PARTY_CAPABLE`
- `THIRD_PARTY_MUTATION`
- `UNKNOWN_RISK`

Examples:

### SUPPLY_CHAIN_IRRELEVANT

- `ls`
- `git status`
- `gofmt`
- reading source/docs

### THIRD_PARTY_CAPABLE

- build/test operations that may fetch or execute third-party code depending on repository state
- generic script execution

### THIRD_PARTY_MUTATION

- `go get`
- `go install`
- `go mod download`
- future npm/pip install operations

### UNKNOWN_RISK

Unrecognized operations that can mutate package/network trust.

Fail conservatively according to the active profile.

## Go Adapter Requirements

Recognize at least:

- `go get`
- `go install`
- `go mod tidy`
- `go mod vendor`
- `go mod download`
- `go env`
- `go work`
- third-party `go run module@version`

Parsing must handle wrappers and shell composition, including:

```text
env FOO=x go get ...
cd dir && go get ...
sh -c 'go get ...'
command go get ...
```

Do not rely on a simple command prefix check.

### Exact Version Rules

Examples that must be denied:

```text
go get github.com/foo/bar
go get github.com/foo/bar@latest
go install example.com/tool@latest
```

A request such as:

```text
go get github.com/foo/bar@v1.7.2
```

must enter the normal trust-evaluation pipeline.

### Go Checksum Integrity

Deny:

```text
GOSUMDB=off
go env -w GOSUMDB=off
GONOSUMDB=*
```

Never disable Go checksum verification as an integration workaround.

## Sensitive Files and Reconciliation

Sensitive state includes:

- `go.mod`
- `go.sum`
- `go.work`
- `go.work.sum`
- `vendor/modules.txt`
- `.github/workflows/*.yml`
- `.github/workflows/*.yaml`

Intercepting edit/write calls is not enough.

Shell scripts, Python, `sed`, generated scripts, and other tools can mutate sensitive files indirectly.

Maintain before/after snapshots and reconcile changes semantically.

## Go Vendoring

If `vendor/modules.txt` exists:

- standard: ask once whether to enforce existing vendor model; default Yes;
- hardened: ask once whether to enforce existing vendor model; default Yes;
- paranoid: enforce.

If no vendor tree exists:

- standard: optional, default No;
- hardened: recommend Enable but allow continuing without vendoring;
- paranoid: mandatory before dependency-changing operations can complete.

After dependency graph mutation:

```text
dependencyGraphDirty = true
```

If vendor enforcement is active:

```text
vendorState = stale
```

After successful `go mod vendor`:

```text
vendorState = current
```

Hardened and Paranoid must not report security-complete state while enforced vendor state remains stale.

## Release Cooldown

Default minimum release age:

```text
10 days
```

Behavior for artifacts newer than the minimum:

- standard: `WARN + ASK`
- hardened: `DENY` with explicit one-shot override
- paranoid: `DENY` with reason-required exceptional override

## Identity and Repository Protection

Similarity checks use an explicit user-controlled trust corpus.

The trust corpus is not an allow-list.

Analyze module identity by component:

- host
- owner
- repository
- subpath

Use:

- Damerau-Levenshtein distance;
- normalized edit distance;
- absolute distance for short identifiers;
- duplicate/missing/added-character signals;
- separator/prefix/suffix variants;
- exact protected repository name under a different owner;
- owner similarity with identical repository name.

Initial normalized-distance thresholds:

- standard: `0.08`
- hardened: `0.15`
- paranoid: `0.25`

If no trust corpus exists:

- disable local similarity analysis rather than guessing;
- paranoid emits a prominent limitation warning;
- absence of a corpus alone does not deny all dependency operations.

## Socket Integration

Socket is an external provider, not a replacement for local checks.

### hardened

- Socket is not required for Hardened to function.
- Scans are optional/recommended when configured.
- Firewall is ask-once per project.
- Default interactive choice is Enable.
- User may decline.
- Decline/enable state is persisted and audited.
- Local Hardened policy continues if declined.
- Headless mode does not prompt; Firewall is disabled unless explicitly configured and an audit warning is emitted.

### paranoid

For new trust decisions:

- artifact evaluation is mandatory;
- manifest/project scan is mandatory after dependency mutation;
- Firewall is mandatory for dependency fetches;
- provider health/auth/version must be valid;
- timeout/quota/unavailable/unscanned/unsupported means `DENY`;
- unchanged approved vendored code may build/test offline.

Canonical paranoid dependency flow:

```text
go get module@version
→ Go adapter / exact version
→ local trust + release age + vulnerability checks
→ Socket artifact evaluation
→ human approval
→ Socket Firewall protected fetch
→ go.mod/go.sum semantic diff
→ go mod vendor
→ Socket manifest/project scan
→ SupplyGuard verification
→ audit / security-complete state
```

## Generic Policies

All profiles deny immediate execution pipelines:

```text
curl ... | sh
curl ... | bash
wget ... | sh
wget ... | bash
```

A download without immediate execution is a different event and must be evaluated under network/artifact policy.

GitHub Actions immutable-reference policy belongs in the generic layer.

Hardened and Paranoid should deny mutable references such as:

```yaml
uses: actions/checkout@v4
```

and require/prefer full 40-character commit SHA references.

## Human Approval

Approval is a security primitive.

The agent cannot approve its own trust decision.

A scoped approval should bind to:

- policy
- artifact
- exact version or operation
- one execution
- audit record

A dependency approval should include, where available:

- ecosystem
- artifact
- exact version
- purpose
- whether stdlib was considered
- why stdlib is insufficient
- release age
- vulnerability findings
- similarity/repository findings
- transitive impact
- vendor state
- Socket result when applicable

Do not implement broad "Always approve this dependency" behavior in v1.

A version change is a new trust decision.

## Configuration and State Paths

Canonical paths:

```text
Global policy:
~/.config/pi-supplyguard/config.yaml

Project policy:
<repo>/.supplyguard.yaml

Global protected identities:
~/.config/pi-supplyguard/trust.yaml

Project protected identities:
<repo>/.supplyguard-trust.yaml

Local remembered state:
~/.local/state/pi-supplyguard/state.json

Audit log:
~/.local/state/pi-supplyguard/audit.jsonl
```

Precedence:

```text
compiled safe minimums
→ global configuration
→ project configuration
→ scoped runtime decision
```

Workstation-only decisions such as Hardened Firewall opt-in/out and detected vendor mode belong in local state rather than automatically rewriting project files.

## Audit and Privacy

Audit records should include relevant metadata such as:

- timestamp
- profile
- session
- cwd
- branch
- event
- ecosystem
- artifact
- version
- local analysis
- provider status/results
- decision
- approval/override metadata

Never dump raw environment variables.

Never expose:

- Socket credentials
- registry tokens
- npm auth
- GitHub secrets
- other credentials

to model context, audit logs, or worker handoffs.

## SupplyGuard Dependency Policy

Prefer Node.js built-ins for:

- filesystem
- hashing
- fetch/networking
- process handling
- serialization where practical

Do not add runtime dependencies without explicit human approval.

Do not add or upgrade dev dependencies without explicit human approval.

Never use floating versions such as `@latest`.

Implement Damerau-Levenshtein internally unless a very small audited dependency is explicitly justified.

If YAML remains the configuration format, use at most one small pinned YAML parser unless explicitly approved otherwise.

Avoid:

- large frameworks
- unnecessary transitive dependencies
- dynamic runtime plugin loading
- `curl | sh`
- `wget | sh`

## Testing Requirements

Every policy rule requires tests.

Security-sensitive rules require:

- a positive test where the risky operation is blocked or flagged;
- a negative test where legitimate behavior remains allowed.

Required test areas include:

- profile decision contract tables;
- Go command parsing;
- shell wrapper/composition bypass cases;
- semantic go.mod changes;
- vendor state transitions;
- similarity and repository-squatting corpora;
- release-age behavior;
- external-provider failure behavior;
- Hardened Firewall ask-once behavior;
- Paranoid fail-closed behavior;
- installer pipelines;
- GitHub Actions references;
- indirect manifest mutation;
- Chief/worker policy parity.

Do not consider an enforcement rule complete until the actual Pi `tool_call` path has been exercised where relevant.

## Milestone Order

Follow this order unless the human explicitly changes it.

### M1 — Pi skeleton

- `tool_call` hook
- config
- profiles
- decisions
- audit
- UI

### M2 — Go command gate

- `go get`
- `go install`
- `go mod ...`
- `go env`
- `go run`
- exact-version requirements
- GOSUMDB protections

### M3 — Manifest engine

- go.mod/go.sum semantic state
- snapshots
- vendor detection
- vendor drift

### M4 — Human trust gate

- dependency justification
- approval
- scoped overrides
- release cooldown

### M5 — Identity protection

- trust corpus
- Damerau-Levenshtein
- repository-squatting

### M6 — Vulnerability metadata

- OSV
- provider abstraction

### M7 — Socket integration

- artifact scan
- manifest scan
- provider health/version
- Hardened optional Firewall
- Paranoid mandatory Firewall

### M8 — Generic policies

- GitHub Actions full-SHA pinning
- `curl|sh` / `wget|sh`
- network events

### M9 — Adversarial hardening

- indirect manifest mutation
- headless behavior
- Chief/worker parity
- bypass corpus

## Review Requirements

The Chief must inspect actual diffs and test output.

For important security-sensitive work, prefer an independent reviewer worker using a different model family when available.

Never automatically:

- push
- create or merge remote PRs
- tag
- publish to npm
- create a release
- change remote repository settings
- expose credentials

All remote mutation, release, and publish operations require explicit human approval.
