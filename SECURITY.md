# Security Policy

## Supported state

`pi-supplyguard` is **pre-release software** (version 0.1.x). Milestones M1
(Pi skeleton: tool-call hook, configuration, profiles, decisions, audit),
M2 (Go command gate) and M3 (manifest engine: snapshots, semantic `go.mod`
state, vendor detection and drift) and M4 (dependency justification, release
cooldown, scoped one-shot overrides) and M8 (generic policies: installer
pipelines, GitHub Actions pinning, network events) and M5 (identity protection)
are complete. M6, M7 and M9 are not implemented. See
[Current enforcement status](#current-enforcement-status) below and
[`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) for the full honesty contract.

Security fixes are provided on a best-effort basis while the project is
pre-release.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

This project does **not yet have a dedicated published security contact**
(email or platform channel). That is itself a known limitation, stated here
explicitly rather than papered over with an invented address. Until a private
channel is announced in this file, report vulnerabilities privately to the
maintainers through whatever private channel the copy of this software was
distributed to you with (for example, private vulnerability reporting on the
repository hosting your copy).

Please include, where possible: a description of the issue, reproduction
steps, affected versions/commits, and your assessment of impact. We aim to
acknowledge reports promptly.

## Scope

### What pi-supplyguard protects against (today)

- An AI agent adding, upgrading or executing third-party Go dependencies
  through commands (`go get`, `go install`, `go mod download`,
  `go mod tidy/vendor`, `go run module@version`) — including through shell
  wrappers and composition (`env VAR=x …`, `cd dir && …`, `sh -c '…'`,
  `command go …`, `sudo`/`nice`/`timeout` wrappers).
- Unversioned and floating dependency/tool references (`@latest`, `v1`,
  branch names) — denied; exact versions require explicit human approval.
- Disabling or weakening Go checksum verification (`GOSUMDB=off`,
  `GONOSUMDB`, `GOFLAGS=-insecure`, `GOINSECURE`, `GOPRIVATE=*`) — denied in
  every profile.
- Unrecognized package/network-capable commands — classified as
  `UNKNOWN_RISK` and handled conservatively (ask/ask/deny by profile).
- Itself: internal errors block the tool call (fail closed), headless
  approval gates are denied, and decisions are written to a local audit log.
- Delegated headless sub-agents: they inherit the same enforcement and
  cannot pass a human approval gate, so they cannot perform dependency
  mutations at all.

### What pi-supplyguard does NOT protect against

It is **not** an operating-system sandbox, not an EDR, and not a replacement
for package managers, Socket, OSV, CI or SBOM platforms (design non-goals,
[`docs/SPEC.md` §2.2](docs/SPEC.md)). It does not prove that any package is
benign.

Specific limits of the current implementation (details in
[`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md)):

- **Manifest reconciliation is retrospective.** A `go.mod` rewritten by `sed`,
  a script or generated code IS detected and gated, but on the *next* tool
  call: Pi's hook runs before a tool executes, and the `tool_result` event
  cannot block. The boundary is "the agent cannot keep working after an
  unapproved manifest edit", not "the edit cannot happen". The baseline is
  established on the first tool call in a session, so changes made while Pi
  was not running are the starting point rather than a mutation, and a single
  human-approved manifest-writing command covers everything else it changed in
  the same tool call.
- The approval object carries the agent's rationale and the release age, but
  not the vulnerability, similarity or transitive-impact findings SPEC §11.2
  also lists (M5, M6).
- The release-age lookup is SupplyGuard's only outbound request. `GOPRIVATE`,
  `GONOPROXY` and `GOPROXY=off` are honored before a request is built, so a
  private module path is never sent to a public proxy — and its age is
  therefore never checked either.
- Identity analysis protects only the identities a corpus names, and does
  nothing at all without one (SPEC §12.6). It has no Unicode or homoglyph
  normalization, so a lookalike built from non-Latin characters passes.
- No vulnerability intelligence such as OSV (M6).
- No Socket scans, Socket Firewall or provider health checks (M7).
- Generic policy stops where SPEC §15 stops: a download and its execution in
  two separate steps is a network event rather than a pipeline, container image
  digests are not pinned, and mutable action references already committed are
  reported rather than gated.
- The Pi host does not re-validate tool input after a handler approves it: a
  hostile co-installed extension could rewrite an approved command
  (documented; tracked for M9). SupplyGuard itself never rewrites tool input.
- A persistent SupplyGuard failure blocks all tool calls by design (fail
  closed) — operationally severe, deliberate.

## Threat model summary

SupplyGuard assumes the AI agent may act accidentally or adversarially:
introducing third-party software, executing ephemeral packages, weakening
checksum verification, altering CI dependencies, bypassing manifest controls,
or delegating risky behavior to another agent. The full threat model is
[`docs/SPEC.md` §3](docs/SPEC.md).

Trust boundaries:

- **Inside:** the SupplyGuard policy engine, its configuration files, the
  audit log, and the human answering an approval prompt. Local policy is
  always authoritative; external intelligence can only tighten a decision,
  never weaken it.
- **Boundary:** the Pi `tool_call` interception point. Decisions
  (`ALLOW`/`WARN`/`ASK`/`DENY`, most restrictive wins) are enforced before
  tool execution for `DENY`.
- **Outside:** the agent, tool input, project files, and future external
  providers — all treated as untrusted input to policy evaluation.

## Current enforcement status

| Area | Status |
|---|---|
| Every tool call classified; irrelevant ops untouched | **Enforced** (M1) |
| Profiles `standard`/`hardened`/`paranoid`, tighten-only layering | **Enforced** (M1) |
| Session profile tightening command (never lowering) | **Enforced** (M1) |
| Audit log with decision/approval metadata, redaction | **Enforced** (M1) |
| Fail closed on internal errors; headless `ASK` denied | **Enforced** (M1) |
| Go command recognition incl. shell wrappers/composition | **Enforced** (M2) |
| Exact-version requirement; `@latest`/floating denied | **Enforced** (M2) |
| Checksum-bypass denial (`GOSUMDB=off` etc.) | **Enforced** (M2) |
| Manifest snapshots / indirect `go.mod`-`go.sum` mutation detection | **Enforced** (M3, retrospective — see limits above) |
| Vendor detection / drift; ask-once vendor model | **Enforced** (M3) |
| Dependency justification required before a trust decision | **Enforced** (M4) |
| Release cooldown, per profile, with a proxy-outage posture | **Enforced** (M4) |
| Scoped one-shot overrides, reason-required in paranoid | **Enforced** (M4) |
| Typosquatting / reposquatting against a trust corpus | **Enforced** (M5) |
| Vulnerability metadata (OSV) | Not yet enforced (M6) |
| Socket scans / Firewall / provider health | Not yet enforced (M7) |
| `curl \| sh` / `wget \| sh` denial, in every profile | **Enforced** (M8) |
| GitHub Actions full-SHA pinning; network events | **Enforced** (M8) |
| Adversarial hardening (hostile extensions, bypass corpus) | Not yet enforced (M9) |

## Supply-chain policy for this project itself

`pi-supplyguard` holds itself to the standard it enforces: one pinned runtime
dependency (`yaml@2.9.0`), exact-pinned dev dependencies, no floating
versions in `dependencies`/`devDependencies` (the optional host
peerDependency is deliberately `*`, see KNOWN-GAPS §1.9), Node built-ins
preferred, and human review required for any
dependency change. See [`README.md`](README.md) and [`AGENTS.md`](AGENTS.md).
