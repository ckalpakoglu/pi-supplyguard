# pi-supplyguard — Final Technical Specification v1.0

**Version:** 1.0 — Final design baseline  
**Date:** 25 August 2026  
**Target:** Pi Coding Agent extension  
**Initial ecosystem:** Go / Go Modules  
**Future ecosystems:** npm/Node.js, Python, Cargo, others via adapters  
**Default profile:** `standard`  
**Status:** Implementation-ready technical specification

> **Core product definition:** A policy enforcement layer for AI coding agents that makes dependency, build, tooling, and CI supply-chain changes explicit, reviewable, and enforceable before execution.

---

## Final Profile Decision

| Profile | Socket security scans | Socket Firewall | Failure posture for new trust decisions |
|---|---|---|---|
| `standard` | Optional / off by default | Off by default | Local SupplyGuard policy |
| `hardened` | Optional/recommended; enabled when configured | Optional; ask once per project, default Enable | Local policy remains active if user declines Firewall |
| `paranoid` | Mandatory artifact + manifest scan | Mandatory | Fail closed if Socket cannot evaluate/fetch-protect a new artifact |

Hardened Socket Firewall behavior is intentionally different from Paranoid:

- Hardened prompts once per project.
- The user may continue without Firewall.
- The choice is persisted and audited.
- Paranoid does not offer this bypass during normal operation.

---

# 1. Executive Summary

`pi-supplyguard` is a Pi extension that intercepts supply-chain-relevant agent actions before execution, normalizes them into ecosystem-independent security events, evaluates local policy, optionally enriches them with external intelligence, and returns:

- `ALLOW`
- `WARN`
- `ASK`
- `DENY`

The first production adapter targets Go while the core remains ecosystem-agnostic.

The design assumes AI coding agents can change dependencies through:

- commands;
- direct file edits;
- generated scripts;
- CI configuration;
- delegated workers.

Therefore the security model is not limited to command regexes. It combines:

- tool-call interception;
- semantic manifest state;
- before/after integrity snapshots;
- repository configuration;
- human approval;
- independent verification.

## 1.1 Key Outcomes

- `standard` is the default profile.
- `hardened` and `paranoid` increase enforcement rather than only increasing warning verbosity.
- Go vendoring adapts to the project: existing vendor state is detected and confirmed; Paranoid requires vendoring.
- Typosquatting and repository-squatting checks are config-driven and use a user-controlled protected identity corpus.
- Every Pi tool call is classified.
- Only supply-chain-relevant and third-party-capable operations are routed through relevant gates/providers.
- Paranoid requires Socket artifact/manifest analysis and Socket Firewall protection for new dependency trust decisions.
- Hardened offers Socket Firewall as an ask-once, per-project optional control with default selection Enable.
- Chief and delegated workers inherit the same global enforcement.
- npm and Python adapters can be added without changing the policy engine.

---

# 2. Goals and Non-Goals

## 2.1 Goals

- Move supply-chain controls from prompts into executable policy.
- Stop or explicitly approve dependency/tool/CI trust decisions before execution.
- Preserve low-friction normal development while making security profiles meaningfully different.
- Provide explainable decisions and durable audit evidence.
- Support offline/vendored steady-state development after admission controls complete.
- Keep the core independent of Go, npm, Python, or any package manager.

## 2.2 Non-Goals

SupplyGuard is not intended to:

- provide full operating-system sandboxing or EDR;
- replace package managers, Socket, OSV, CI, or SBOM platforms;
- prove that a package is benign;
- autonomously authorize release/merge/push;
- send every harmless shell command to Socket or another remote provider.

---

# 3. Threat Model

SupplyGuard assumes an agent may accidentally or adversarially:

- introduce third-party software;
- execute ephemeral packages;
- weaken checksum verification;
- alter CI dependencies;
- bypass manifest controls;
- delegate work to another agent that repeats the same risky behavior.

## 3.1 Threats in Scope

- Unpinned and floating dependencies/tools, including `@latest`.
- Compromised newly released package versions.
- Dependency confusion.
- Typosquatting.
- Owner/repository impersonation and reposquatting.
- Known vulnerable or malicious packages, including transitive dependencies where provider data is available.
- `GOSUMDB` or equivalent integrity-control bypass.
- Direct and indirect mutation of `go.mod`, `go.sum`, and future lockfiles.
- Stale vendor trees after dependency graph changes.
- Mutable GitHub Actions references.
- `curl|sh` / `wget|sh`.
- Ephemeral third-party execution such as `npx`, `go run module@version`, future `uvx`/`pipx`.
- Agent delegation as a security-control bypass.
- External scanner outage or unscanned artifacts in Paranoid mode.

---

# 4. Security Profiles

Profiles are ordered:

```text
standard < hardened < paranoid
```

Effective profile:

```text
effectiveProfile = max(globalProfile, projectProfile)
```

A project may tighten the global baseline but may not silently weaken it.

## 4.1 standard

Security-conscious normal development.

Characteristics:

- blocks invariant violations;
- asks on new trust decisions;
- does not force a project into a new dependency-management model merely because the plugin was installed.

## 4.2 hardened

Production/security-sensitive development.

Characteristics:

- existing project controls are strongly enforced;
- warnings become gates where appropriate;
- Socket integration is recommended;
- Socket Firewall remains optional by explicit design;
- user is asked once per project;
- default selection is Enable;
- user may Continue without Firewall;
- decision is persisted and audited.

### Hardened Socket Firewall Prompt

```text
Hardened profile: Socket Firewall is available.

Protect dependency fetches with Socket Firewall for this project?

> Enable Firewall (recommended)
  Continue without Firewall
```

In headless mode:

- optional Firewall is disabled unless explicitly configured;
- SupplyGuard emits an audit warning;
- local Hardened policy remains enforced.

## 4.3 paranoid

Dependency compromise is treated as an active threat.

Characteristics:

- Go vendoring is mandatory;
- external Socket security evaluation is mandatory for new trust decisions;
- Socket Firewall is mandatory for dependency fetches;
- failures are fail-closed;
- existing already-baselined vendored code may continue to build/test offline when Socket is unavailable.

## 4.4 Profile Policy Matrix

| Control | standard | hardened | paranoid |
|---|---|---|---|
| Exact versions | Required | Required | Required |
| `@latest` / floating dependency | Deny | Deny | Deny |
| New dependency / upgrade | Ask | Ask | Ask |
| GOSUMDB disable | Deny | Deny | Deny |
| Critical known vulnerability | Deny | Deny | Deny |
| High known vulnerability | Ask | Deny / override | Deny / exceptional override |
| Release age < minimum | Warn + Ask | Deny / override | Deny / reason-required override |
| Existing Go vendor tree | Ask → enforce | Ask → enforce | Enforce |
| No Go vendor tree | Optional | Recommend | Mandatory |
| Vendor drift | Warn / Ask | Deny completion | Deny completion |
| Trust corpus similarity | Config-driven, low sensitivity | Config-driven, medium sensitivity | Config-driven, high sensitivity |
| Repo-squat signal | Ask | Deny / override | Deny / reason-required override |
| Mutable GitHub Action | Ask / Deny | Deny | Deny |
| `curl|sh` / `wget|sh` | Deny | Deny | Deny |
| Socket artifact/manifest scan | Optional | Optional / recommended when configured | Mandatory |
| Socket Firewall | Off by default | Ask once; optional; default Enable | Mandatory |
| Socket provider unavailable | No special gate unless configured | Local policy continues if optional integration | Fail closed for new trust decisions |
| Build network | Allowed/audited | Ask/audit | Deny by default; approved admission path only |

---

# 5. High-Level Architecture

```text
Pi tool_call
    |
    v
Event Classifier
    |
    +--> supply-chain irrelevant --> normal execution
    |
    v
Ecosystem Adapter Registry
    |
    +--> Go adapter (v1)
    +--> npm adapter (future)
    +--> Python adapter (future)
    |
    v
Normalized SupplyChainEvent
    |
    +--> local policy / version / vendor / checksum
    +--> identity & squatting analysis
    +--> release-age & vulnerability providers
    +--> Socket provider (profile-dependent)
    |
    v
Policy Engine
    |
    +--> ALLOW
    +--> WARN
    +--> ASK --> Human gate
    +--> DENY
    |
    v
Audit + project security state
```

## 5.1 Design Rule: Classify All Tool Calls, Remotely Scan Only Relevant Ones

Every Pi tool call passes through SupplyGuard classification.

Only calls that can introduce, fetch, execute, or mutate third-party trust are sent through Socket checks.

| Classification | Examples | Paranoid behavior |
|---|---|---|
| `SUPPLY_CHAIN_IRRELEVANT` | `ls`, `git status`, `gofmt`, read README | Local/normal execution |
| `THIRD_PARTY_CAPABLE` | build/test without enforced vendor, script execution | Inspect project state; require protected path when third-party fetch/exec is possible |
| `THIRD_PARTY_MUTATION` | `go get`, `go install`, `go mod download`, future npm/pip installs | Local gate + Socket + Firewall + approval |
| `UNKNOWN_RISK` | unrecognized tool/script capable of package/network mutation | Fail conservative: ASK/DENY based on profile |

---

# 6. Core Event Model

```ts
type SupplyChainEvent =
  | DependencyAdd
  | DependencyUpgrade
  | DependencyDowngrade
  | DependencyRemove
  | DependencyReplace
  | ToolInstall
  | ToolUpgrade
  | ThirdPartyExecution
  | LockfileMutation
  | VendorDrift
  | ChecksumBypass
  | RegistryAccess
  | DependencyFetch
  | CIReferenceAdd
  | CIReferenceChange
  | NetworkRequirement
  | SecurityGateChange
  | SecurityBypass;
```

## 6.1 Decision Model

```text
ALLOW < WARN < ASK < DENY
```

When multiple checks return decisions:

```text
finalDecision = mostRestrictive(results...)
```

External intelligence is additive and may never weaken a local SupplyGuard decision.

---

# 7. Ecosystem Adapter Contract

Conceptual interface:

```ts
interface EcosystemAdapter {
  id: string;
  detectProject(ctx): Promise<ProjectDetection>;
  inspectCommand(command, ctx): Promise<SupplyChainEvent[]>;
  inspectFileMutation(mutation, ctx): Promise<SupplyChainEvent[]>;
  inspectProjectState(ctx): Promise<SupplyChainEvent[]>;
  verify(ctx): Promise<VerificationResult[]>;
}
```

The core policy engine must never contain hard-coded branches such as `go get` or `npm install`.

Ecosystem-specific commands and manifests are normalized by adapters.

---

# 8. Configuration and State

## 8.1 Paths

| Purpose | Path |
|---|---|
| Global policy | `~/.config/pi-supplyguard/config.yaml` |
| Project policy | `<repo>/.supplyguard.yaml` |
| Global protected identities | `~/.config/pi-supplyguard/trust.yaml` |
| Project protected identities | `<repo>/.supplyguard-trust.yaml` |
| Local remembered decisions/state | `~/.local/state/pi-supplyguard/state.json` |
| Audit log | `~/.local/state/pi-supplyguard/audit.jsonl` |

## 8.2 Precedence

```text
compiled safe minimums
→ global configuration
→ project configuration
→ scoped runtime decision
```

Project configuration may tighten the effective policy but may not silently lower the global baseline.

Workstation-specific decisions such as Hardened Socket Firewall opt-in/out and detected vendor mode are persisted in local state rather than automatically modifying the repository.

## 8.3 Example Hardened Configuration

```yaml
version: 1
profile: hardened

releaseAge:
  minimumDays: 10

vulnerabilities:
  enabled: true
  provider: osv

squatting:
  enabled: auto

githubActions:
  requireImmutableReferences: true

socket:
  enabled: auto
  artifactScan: recommended
  manifestScan: recommended
  firewall:
    mode: ask
    defaultChoice: enable
  failClosed: false

go:
  vendor: auto

audit:
  enabled: true
```

## 8.4 Paranoid Effective Socket Configuration

```yaml
profile: paranoid

socket:
  required: true
  mode: hybrid
  failClosed: true
  artifactScan:
    required: true
  manifestScan:
    required: true
  firewall:
    requiredForNetworkFetch: true
  allowBypassOverride: false

go:
  vendor: enforce
```

---

# 9. Go Adapter — Project and Vendor Model

## 9.1 Project Detection

Signals:

- strong signal: `go.mod`
- workspace signal: `go.work`
- dependency integrity signal: `go.sum`
- vendoring signal: `vendor/modules.txt`
- secondary signal: `*.go`

## 9.2 Existing Vendor Directory

If `vendor/modules.txt` exists:

- interactive Standard/Hardened sessions ask once whether to continue enforcing repository vendor mode;
- default is Yes;
- Paranoid enforces vendoring without a weakening choice.

Prompt:

```text
Vendored Go dependencies detected.

Continue enforcing the repository vendor model?

> Yes
  No
```

## 9.3 Vendor Absent

| Profile | Interactive behavior | Headless behavior |
|---|---|---|
| standard | Ask whether to enable vendoring; default No | Continue without vendoring |
| hardened | Recommend Enable; allow Continue without vendoring | Continue + audit warning unless config enforces |
| paranoid | Initialize vendoring or cancel | Deny dependency-changing operation |

## 9.4 Vendor Consistency State

```text
dependency graph mutation
→ dependencyGraphDirty = true

if vendor mode enabled
→ vendorState = stale

go mod vendor succeeds
→ vendorState = current
```

Hardened and Paranoid tasks cannot reach a clean completion state with a stale vendor tree when vendor enforcement is active.

---

# 10. Go Command and Manifest Enforcement

## 10.1 Commands Recognized in v1

- `go get`
- `go install`
- `go mod tidy`
- `go mod vendor`
- `go mod download`
- `go env`
- `go work`
- `go run module@version` / third-party execution forms

The parser must handle wrappers and shell composition such as:

```text
env FOO=x go get ...
cd dir && go get ...
sh -c 'go get ...'
command go get ...
```

It must not rely on `startsWith("go get")`.

## 10.2 Version Policy

DENY:

```text
go get github.com/foo/bar
go get github.com/foo/bar@latest
go install example.com/tool@latest
```

EVALUATE:

```text
go get github.com/foo/bar@v1.7.2
```

## 10.3 Checksum Integrity

DENY:

```text
GOSUMDB=off
go env -w GOSUMDB=off
GONOSUMDB=*
```

A Socket/registry/proxy integration may not disable Go checksum verification as a workaround.

TLS/proxy trust must be configured correctly instead of weakening GOSUMDB.

## 10.4 Sensitive File Mutation

Sensitive files:

- `go.mod`
- `go.sum`
- `go.work`
- `go.work.sum`
- `vendor/modules.txt`
- `.github/workflows/*.yml`
- `.github/workflows/*.yaml`

SupplyGuard intercepts Pi edit/write operations to sensitive files, but this is not sufficient because shell/Python/sed/generated scripts can mutate them indirectly.

Repository manifest-integrity snapshots are therefore part of the security model.

## 10.5 Semantic `go.mod` Classification

At minimum:

- `DEPENDENCY_ADD`
- `DEPENDENCY_UPGRADE`
- `DEPENDENCY_DOWNGRADE`
- `DEPENDENCY_REMOVE`
- `REPLACE_ADD`
- `REPLACE_CHANGE`
- `REPLACE_REMOVE`
- `EXCLUDE_ADD`
- `EXCLUDE_REMOVE`

Remote replace directives are higher risk than local development replaces.

All dependency-relevant changes enter the normal trust decision pipeline.

---

# 11. Release Cooldown and Dependency Approval

## 11.1 Default Cooldown

```text
minimumReleaseAgeDays = 10
```

| Profile | Artifact newer than minimum |
|---|---|
| standard | WARN + ASK |
| hardened | DENY with explicit one-shot override |
| paranoid | DENY with reason-required exceptional override |

## 11.2 Approval Object

Dependency approval requires:

- ecosystem;
- artifact;
- exact version;
- purpose;
- `stdlibConsidered`;
- reason stdlib is insufficient;
- release age;
- vulnerability findings;
- similarity/repository findings;
- transitive impact when available;
- vendor state;
- Socket result when applicable.

## 11.3 Approval UX

Example:

```text
SupplyGuard — NEW GO DEPENDENCY

Module: github.com/foo/bar
Version: v1.7.2
Profile: hardened

Exact version            PASS
Release age              94 days
Known vulnerabilities    none
Protected-name conflict  none
Vendoring                pending
Stdlib considered        yes
Socket                    pass / not configured
Firewall                  enabled / declined

> Approve once
  Deny
```

v1 does not include "Always approve this dependency".

A version change is a new trust decision.

---

# 12. Typosquatting and Repository-Squatting

## 12.1 User-Controlled Trust Corpus

Similarity analysis is driven by an explicit protected identity corpus.

It is not a package allow-list.

SupplyGuard does not invent authoritative ownership relationships.

Example:

```yaml
version: 1
protected:
  go:
    modules:
      - module: github.com/google/uuid
        repository: github.com/google/uuid
      - module: github.com/stretchr/testify
        repository: github.com/stretchr/testify
      - module: golang.org/x/sync
        repository: github.com/golang/sync
    owners:
      - google
      - golang
      - hashicorp
      - kubernetes
      - prometheus
      - stretchr
```

## 12.2 Component-Aware Normalization

Example:

```text
github.com/google/uuid

host    = github.com
owner   = google
repo    = uuid
subpath = null
```

Whole module paths are not compared as one string.

## 12.3 Similarity Algorithms

- Damerau-Levenshtein distance.
- Normalized edit distance for longer identifiers.
- Absolute edit distance for short identifiers (length ≤ 5).
- Duplicate/missing/added-character signals.
- Separator and prefix/suffix variants.
- Exact repository name under a different owner.
- Owner similarity plus identical repository name.
- Optional future Unicode/homoglyph normalization.

## 12.4 Default Similarity Sensitivity

| Profile | Max normalized distance | Intent |
|---|---:|---|
| standard | 0.08 | only obvious lexical neighbors |
| hardened | 0.15 | moderate similarity sensitivity |
| paranoid | 0.25 | aggressive candidate screening |

These are initial heuristics and must be calibrated against true-positive and false-positive corpora before stable release.

## 12.5 Repo-Squatting Signal

An exact protected repository name under a different owner is a distinct signal even when edit distance is large.

Example:

```text
protected: github.com/google/uuid
candidate: github.com/random-owner/uuid
```

## 12.6 No Trust Corpus

If no trust corpus exists:

- local similarity analysis is disabled rather than guessed;
- Paranoid emits a prominent warning that protection is limited;
- missing corpus alone does not block every dependency operation.

---

# 13. Socket.dev Integration

Socket is an external security provider, not a replacement for local SupplyGuard checks.

## 13.1 Provider Abstraction

```ts
interface ExternalSupplyChainProvider {
  id: string;
  checkArtifact(artifact): Promise<ArtifactSecurityResult>;
  checkManifest(project): Promise<ProjectSecurityResult>;
  supportsInstallFirewall(ecosystem): Promise<boolean>;
  health(): Promise<ProviderHealth>;
}
```

## 13.2 Modes

```text
disabled | scan | firewall | hybrid
```

`hybrid` means artifact-level inspection + manifest/project scan + install/fetch protection through Socket Firewall where supported.

## 13.3 Hardened Behavior

1. Hardened does not require Socket to be installed/configured.
2. If Socket scanning is configured, artifact and manifest scans are recommended and additive.
3. If Firewall capability exists and no per-project choice is stored, prompt once:
   - Enable Firewall (recommended)
   - Continue without Firewall
4. Default interactive selection is Enable.
5. Decline keeps local Hardened policy active.
6. Choice is persisted and audited.
7. In headless mode, optional Firewall is disabled unless explicitly configured.
8. Headless mode writes an audit warning.
9. Decision can later be changed through configuration or SupplyGuard commands.

## 13.4 Paranoid Behavior

1. Artifact evaluation mandatory for every new/changed third-party artifact.
2. Manifest/project scan mandatory after dependency graph mutation.
3. Socket Firewall mandatory for network package/module fetches.
4. Provider health/authentication/version must be valid.
5. Timeout, quota, unavailable, unscanned, unsupported fail closed for new trust decisions.
6. Already-approved vendored dependencies may continue to build/test offline when the graph is unchanged.
7. Socket-unavailable is not a normal one-shot approval path.

## 13.5 Decision Composition

```text
finalDecision = mostRestrictive(
  localPolicy,
  identityChecks,
  releaseAge,
  vulnerabilityChecks,
  socketResult
)
```

A clean Socket result cannot override a local reposquatting, GOSUMDB, vendoring, or release-age policy violation.

## 13.6 Canonical Paranoid Go Dependency Flow

```text
go get module@version
→ Go adapter / exact version
→ local trust + release age + OSV
→ Socket artifact evaluation
→ human approval
→ Socket Firewall protected fetch
→ go.mod/go.sum semantic diff
→ go mod vendor
→ Socket manifest/project scan
→ SupplyGuard verification
→ audit / security-complete state
```

## 13.7 Third-Party Execution

Operations that download and immediately execute third-party code are treated at least as strictly as dependency additions.

Examples:

- future npm `npx` / `npm exec`;
- Go module execution forms;
- `uvx`;
- `pipx`.

Paranoid requires:

- exact versioning;
- Socket evaluation;
- protected fetch;
- explicit approval;
- audit.

## 13.8 Provider Failures

| Failure | standard | hardened | paranoid |
|---|---|---|---|
| Socket unavailable | ignore unless explicitly configured | continue local policy; warn/audit if expected | deny new trust decision |
| Auth failure | warn if configured | warn/ASK; local policy remains | deny new trust decision |
| Timeout/quota | warn if configured | warn/ASK; local policy remains | deny new trust decision |
| Unsupported/unscanned artifact | no Socket signal | treat as unknown external evidence | deny new trust decision |
| Existing clean vendored baseline, no mutation | normal build | normal build | offline build/test allowed |

## 13.9 Firewall Deployment Capability

SupplyGuard must capability-detect Firewall mode rather than assume a single wrapper behavior.

Provider deployment may expose:

- proxy mode;
- registry mode;
- wrapper mode.

For Go, prefer centrally enforceable proxy/registry paths where available.

Never weaken GOSUMDB to make Firewall/proxy integration work.

---

# 14. Manifest Integrity and Bypass Resistance

Tool-call command interception is not a filesystem security boundary.

An agent can mutate `go.mod` through:

- `sed`;
- Python;
- generated scripts;
- another tool.

Therefore v1 includes before/after manifest integrity snapshots.

## 14.1 Snapshot Set

- `go.mod` hash
- `go.sum` hash
- `go.work` hash when present
- `go.work.sum` hash when present
- `vendor/modules.txt` hash
- GitHub workflow file hashes

## 14.2 Reconciliation

```text
tool completes
→ compare sensitive manifest snapshots
→ mutation detected?
→ ecosystem semantic diff
→ generate normalized events
→ invalidate Socket baseline if applicable
→ enforce verification before SECURITY_COMPLETE
```

---

# 15. GitHub Actions and Generic Installer Policies

## 15.1 GitHub Actions

DENY in Hardened/Paranoid:

```yaml
uses: actions/checkout@v4
```

ACCEPT/PREFER:

```yaml
uses: actions/checkout@<40-char-commit-sha> # v4.x.y
```

GitHub Actions policy belongs to the generic core module, not the Go adapter.

## 15.2 Installer Pipelines

DENY in all profiles:

```text
curl ... | sh
curl ... | bash
wget ... | sh
wget ... | bash
```

Downloading a file with curl/wget without immediate execution is a different event and is evaluated by network/artifact policy rather than automatically denied.

---

# 16. Vulnerability Intelligence

The vulnerability-provider interface is ecosystem-independent.

```ts
interface VulnerabilityProvider {
  query(ecosystem, artifact, version): Promise<VulnerabilityFinding[]>;
}
```

OSV can be the default vulnerability provider.

Socket contributes additional package behavior and policy intelligence.

Provider failures follow the active profile failure posture.

Unknown is never silently equivalent to clean in Paranoid.

---

# 17. Human Approval and Overrides

## 17.1 Approval Is a Security Primitive

The agent cannot approve its own trust decision.

Approvals are initiated by:

- SupplyGuard UI;
- explicit trusted configuration.

## 17.2 Scoped Override Model

```text
one policy
+ one artifact
+ one version/operation
+ one execution
+ audit
```

Paranoid release-age or similar exceptional overrides require a human-entered reason.

Disabling the plugin is not the normal override mechanism.

## 17.3 Socket-Specific Bypass

Paranoid Socket unavailability is deliberately not handled as a normal "Approve once" exception.

The operator must:

- restore Socket; or
- explicitly alter machine/global policy.

This prevents scanner outage from becoming a recurring bypass.

---

# 18. Audit and State Model

## 18.1 Audit Record

Representative shape:

```json
{
  "timestamp": "...",
  "profile": "hardened",
  "session": "...",
  "cwd": "...",
  "branch": "agent/auth",
  "event": "dependency-add",
  "ecosystem": "go",
  "artifact": "github.com/foo/bar",
  "version": "v1.7.2",
  "local": {
    "releaseAgeDays": 94,
    "similarity": [],
    "vulnerabilities": []
  },
  "socket": {
    "configured": true,
    "artifactScan": "pass",
    "manifestScan": "pass",
    "firewall": "declined-by-user"
  },
  "decision": "approved"
}
```

## 18.2 Hardened Firewall Remembered State

Representative shape:

```json
{
  "/path/to/repo": {
    "profile": "hardened",
    "socket": {
      "firewallDecision": "enabled",
      "decidedAt": "..."
    },
    "go": {
      "vendorMode": "enforce"
    }
  }
}
```

`firewallDecision` may be `enabled` or `declined`.

`vendorMode` may be `enforce` or `optional`.

## 18.3 Secrets and Privacy

- Socket credentials never enter LLM context.
- Socket credentials never enter audit logs.
- Socket credentials never enter worker handoffs.
- Audit does not dump raw environment variables.
- Manifest scans are the default external data path.
- More invasive reachability/source analysis requires explicit configuration.
- Provider health/version may be logged.
- Secret values may not be logged.

---

# 19. Pi Integration

SupplyGuard is installed so Chief, workers, and reviewers receive the same enforcement.

Pi integration primitives include:

- `tool_call` interception;
- blocking/modifying calls;
- prompting through `ctx.ui`;
- registering commands;
- persistent state.

## 19.1 Commands

Planned commands:

- `/supplyguard`
- `/supplyguard-status`
- `/supplyguard-profile`
- `/supplyguard-config`
- `/supplyguard-check`
- `/supplyguard-audit`
- `/supplyguard-socket`

## 19.2 Status Example

```text
SupplyGuard
Profile             hardened
Ecosystem           Go
Vendor              enforced
Trust corpus         47 identities
Cooldown             10 days
OSV                  enabled
Socket scans         configured
Socket Firewall      enabled (project decision)
Pending approvals    0
Security state       clean
```

## 19.3 Chief / Worker Invariant

```text
Chief Pi
  → worker Pi
     → global SupplyGuard
        → same effective baseline
```

Delegation MUST NOT weaken policy.

---

# 20. External Tool Integrity

SupplyGuard should verify the security tooling it relies on.

In Paranoid:

- Socket CLI/Firewall versions should be pinned.
- Digest pinning should be supported where practical.
- A provider that cannot pass its own health/version check cannot authorize new dependency trust decisions.

---

# 21. Implementation Structure

```text
pi-supplyguard/
├── src/index.ts
├── src/core/
│   ├── engine.ts
│   ├── events.ts
│   ├── decisions.ts
│   ├── profiles.ts
│   ├── config.ts
│   ├── state.ts
│   ├── audit.ts
│   └── approval.ts
├── src/adapters/
│   ├── registry.ts
│   └── go/
│       ├── commands.ts
│       ├── modfile.ts
│       ├── vendor.ts
│       ├── project.ts
│       └── verification.ts
├── src/analyzers/
│   ├── similarity.ts
│   ├── repository.ts
│   ├── release-age.ts
│   └── vulnerability.ts
├── src/providers/
│   └── socket/
│       ├── index.ts
│       ├── scan.ts
│       ├── firewall.ts
│       ├── health.ts
│       └── types.ts
├── src/generic/
│   ├── github-actions.ts
│   ├── installers.ts
│   └── network.ts
└── test/
    ├── core/
    ├── go/
    ├── socket/
    ├── fixtures/
    └── integration/
```

---

# 22. Dependency Minimization for SupplyGuard Itself

- Use Node built-ins for filesystem, hashing, and fetch where practical.
- Implement Damerau-Levenshtein internally unless a very small audited dependency is justified.
- Use a single pinned YAML parser only if YAML remains the configuration format.
- Avoid large frameworks.
- Avoid dynamic runtime plugin loading.
- Avoid unnecessary transitive dependencies.
- SupplyGuard itself should be version-pinned and installed from reviewed source/release artifacts.

---

# 23. Testing Strategy

## 23.1 Unit Tests

Cover:

- Go command parsing including `env`, shell composition, and wrappers.
- `go.mod` semantic add/upgrade/downgrade/remove/replace/exclude classification.
- Vendor mode and drift state transitions.
- Damerau-Levenshtein and repository-squatting true/false positive corpora.
- Profile event × decision contract tables.
- Hardened Socket Firewall ask-once, remembered opt-in, and remembered decline.
- Paranoid Socket fail-closed provider outcomes.

## 23.2 Adversarial Bypass Tests

At minimum:

```text
sh -c 'go get foo@latest'
env GOSUMDB=off go test ./...
cd x && go get foo@latest
command go get foo@latest
python modify-go-mod.py
sed -i ... go.mod
worker Pi attempts same dependency operation
```

## 23.3 Socket Security Contract Tests

| Scenario | Expected |
|---|---|
| Socket clean + local clean | continue to approval/allow path |
| Socket deny + local clean | deny |
| Socket clean + local typosquat | deny/local policy wins |
| Paranoid Socket unavailable + new dependency | deny |
| Paranoid Socket unavailable + existing vendored baseline | offline build/test allowed |
| Paranoid unscanned artifact | deny |
| Hardened Firewall available, no decision | prompt once |
| Hardened user declines Firewall | persist decline + audit; local Hardened policy continues |
| Hardened user enables Firewall | persist enable + enforce protected fetch |
| Headless Hardened, no explicit Firewall config | no prompt; Firewall disabled + audit warning |
| Chief/worker difference | none; same global baseline |

---

# 24. MVP and Milestones

| Milestone | Scope |
|---|---|
| M1 — Pi skeleton | `tool_call` hook, config, profiles, decisions, audit, UI |
| M2 — Go command gate | `go get/install/mod/env/run`, exact versions, GOSUMDB |
| M3 — Manifest engine | `go.mod/go.sum` semantic state, snapshots, vendor detection/drift |
| M4 — Human trust gate | dependency justification, approval, scoped overrides, cooldown |
| M5 — Identity protection | trust corpus, Damerau-Levenshtein, reposquatting |
| M6 — Vulnerability metadata | OSV and provider abstraction |
| M7 — Socket integration | artifact/manifest scans, health/version, Hardened optional Firewall, Paranoid mandatory Firewall |
| M8 — Generic policies | GitHub Actions SHA pinning, `curl|sh`, network events |
| M9 — Adversarial hardening | indirect manifest mutation, headless behavior, Chief/workers, bypass corpus |

---

# 25. v1.0 Success Criteria

v1.0 is complete when:

- `standard` is the default profile.
- standard/hardened/paranoid decisions are contract-tested.
- Existing Go vendor projects are detected and preserved.
- Paranoid blocks dependency mutation until Go vendoring is established.
- Unversioned and `@latest` Go dependency/tool operations are blocked.
- `GOSUMDB=off` is blocked.
- Direct and indirect `go.mod/go.sum` changes become semantic events.
- New dependencies/upgrades require human approval.
- Release cooldown and scoped override behavior work per profile.
- Trust corpus enables component-aware typo/repository-squatting analysis.
- Mutable GitHub Actions and installer pipelines are enforced.
- Hardened asks once whether to enable Socket Firewall, remembers the choice, and audits it.
- Paranoid requires Socket artifact + manifest evaluation and protected fetch for new third-party trust decisions.
- Paranoid fails closed on Socket outage/unscanned artifacts for new trust decisions while allowing unchanged vendored offline builds.
- All security decisions and overrides are auditable.
- Chief and spawned workers receive identical global enforcement.
- The core remains ecosystem-independent so npm/Python adapters can be added without policy-engine redesign.

---

# 26. Future Ecosystem Extensions

## 26.1 npm / Node.js

Future scope:

- npm/yarn/pnpm/Bun command adapters;
- `package.json` + lockfile semantics;
- `npx` / `npm exec` as `ThirdPartyExecution`;
- lifecycle-script policy;
- Socket Firewall and scan-provider reuse.

## 26.2 Python

Future scope:

- pip/uv/Poetry adapters;
- `requirements.txt`, `pyproject.toml`, `uv.lock`, `poetry.lock`;
- `uvx` / `pipx` third-party execution;
- Socket provider reuse.

## 26.3 Core Invariant

```text
new ecosystem = new event producer / verifier
NOT a new policy engine
```

---

# 27. Final Security Invariants

1. The core is ecosystem-agnostic; Go is the first adapter.
2. `standard` is the default and does not unexpectedly rewrite existing project conventions.
3. `hardened` meaningfully increases enforcement while Socket Firewall remains an explicit optional per-project decision.
4. `paranoid` requires Go vendoring, mandatory Socket admission checks, and protected dependency fetches.
5. Every Pi tool call is classified; every third-party trust mutation is gated.
6. A clean external provider result never weakens a local policy denial.
7. Human approval cannot be supplied by the agent itself.
8. Overrides are scoped, one-shot, and audited; Paranoid exceptional overrides require a reason.
9. Delegated agents inherit the same global policy.
10. A missing trust corpus never causes SupplyGuard to invent trusted identities.
11. Indirect manifest mutations are reconciled through before/after snapshots.
12. Steady-state Paranoid Go builds should be vendored/offline after dependency admission completes.
13. SupplyGuard itself minimizes and pins its own dependencies.

---

# 28. References

Implementation must verify exact CLI flags and provider behavior against the pinned versions used during development.

Reference topics from the design baseline:

- Pi Extensions — event interception, `tool_call` blocking/modification, `ctx.ui`, commands, state
- Pi Documentation — extension-first coding harness and installation guidance
- Socket ecosystem support — Go Modules support
- Socket Go support
- Socket Firewall Enterprise Proxy Mode — Go Modules HTTP/HTTPS support
- Socket Firewall overview / ecosystem expansion

---

# 29. One-Sentence Product Definition

> **pi-supplyguard** — A policy enforcement layer for AI coding agents that makes dependency, tooling, build, and CI supply-chain trust decisions explicit, independently checked, reviewable, and enforceable before execution.
