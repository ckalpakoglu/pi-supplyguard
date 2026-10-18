# Security Policy

## Supported state

`pi-supplyguard` is **pre-release software** (version 0.1.x). Milestones
M1–M9, the zero-day hardening line M10–M14, and the local policy line
M15–M18 (rules, sensitive-data rails, an experimental paranoid-only execution
classifier) are complete. Socket Firewall and the manifest scan are out of
scope by decision (2026-10-14). See
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

- An AI agent adding, upgrading or executing third-party **Go** dependencies
  (`go get`, `go install`, `go mod download/tidy/vendor`, `go run
  module@version`, `go generate`) or **npm** dependencies (`npm|pnpm|yarn|bun`
  installs and adds, global installs, `npx`) — including through shell
  wrappers and composition (`env VAR=x …`, `cd dir && …`, `sh -c '…'`,
  `command …`, `sudo`/`nice`/`timeout`).
- Unversioned and floating dependency/tool references (`@latest`, `v1`,
  branch names, npm dist-tags) — denied; exact versions require explicit
  human approval and a recorded justification.
- npm lifecycle scripts: a dependency that runs an install script is gated
  with the script body shown to the human.
- Disabling or weakening Go checksum verification (`GOSUMDB=off`,
  `GONOSUMDB`, `GOFLAGS=-insecure`, `GOINSECURE`, `GOPRIVATE=*`) — denied in
  every profile.
- Indirect manifest mutation (`sed`, scripts, generated code) and direct
  writes into vendored trees (`vendor/`, `node_modules/`) by shell command or
  file tool.
- `curl | sh` installer pipelines, including a download executed one step
  later; mutable GitHub Actions references and `docker://` tags.
- Typo- and repository-squatting against a user-controlled corpus, including
  Unicode lookalikes; known vulnerabilities via OSV.
- **Operator-defined actions**, via local policy rules (`policies:`): any
  command, argument, tool or path shape the operator names is warned about,
  put to a human, or denied — offline, in every profile.
- **Credential exfiltration by shape:** a sensitive path (`.env*`, keys,
  `~/.ssh`, `~/.aws`, …) named to or piped into a network tool is denied in
  every profile; any other read of one asks.
- In `paranoid` with the opt-in classifier: **harmful executions** the agent
  attempts (destructive, reverse shells, obfuscated payloads) are put to a
  human — experimental, ASK-capped, behind the deterministic rails.
- Unrecognized package/network-capable commands — classified as
  `UNKNOWN_RISK` and handled conservatively (ask/ask/deny by profile).
- Itself: internal errors block the tool call (fail closed), headless
  approval gates are denied, and decisions are written to a local audit log.
- Delegated headless sub-agents: they inherit the same enforcement and cannot
  pass a human approval gate, so they cannot perform dependency mutations at
  all.

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
  was not running are the starting point rather than a mutation.
- **Local policy rules see shapes, not content.** A rule matches argv, tool
  names and path operands. `python3 rewrite.py` touching a protected
  directory is invisible to a `writePrefix` rule unless the path is on the
  command line; a flag hidden in a variable (`git push $F`) is not seen;
  symlinks are not resolved (KNOWN-GAPS §1.18).
- **Sensitive-data rails read operands, not programs.**
  `python3 -c "open('.env')"` and `curl -d @- < .env` are not seen by the
  rails; a secret in a file not named as sensitive is not protected
  (KNOWN-GAPS §1.19).
- **The execution classifier is probabilistic and fail-soft.** It can miss
  harm and flag benign commands; when unreachable, local policy stands. In
  paranoid with it enabled, redacted command and script text leave the
  machine (KNOWN-GAPS §1.20).
- The approval prompt shows every finding — justification, release age,
  vulnerabilities, similarity, content scan, matched rules — but not the
  transitive impact SPEC §11.2 also lists.
- **Outbound requests:** the Go module proxy (release dates), OSV
  (advisories), the Socket CLI when installed, and the opt-in Jev and
  repository-signal providers. `GOPRIVATE`, `GONOPROXY` and `GOPROXY=off` are
  honored before any request is built, so a private module path is never sent
  to a public service — and its age and advisories are therefore never
  checked either.
- npm artifacts get no release-age, OSV or content scan yet; their evidence is
  lifecycle scripts, lockfile metadata and the justification.
- Identity analysis protects only the identities a corpus names, and does
  nothing at all without one (SPEC §12.6).
- Vulnerability data is only as good as OSV's coverage and as fresh as the
  per-process cache; an advisory with no stated severity is treated as
  unresolved rather than assigned one.
- Socket integration is the CLI only: artifact scoring and provider health, no
  Firewall and no manifest scan — both out of scope by decision (2026-10-14),
  so this is no longer a SPEC §13.4 shortfall.
  `socket package score` also requires a Socket API token, without which every
  scan is "unavailable" — a warning below Paranoid and a denial in it.
- Mutable action references already committed are reported, not gated; only
  newly introduced ones are gated.
- A hostile co-installed extension that rewrites tool input after SupplyGuard
  approved it is **detected and audited**, not prevented: the hosts do not
  re-run hooks on a revision. SupplyGuard itself never rewrites tool input.
- A persistent SupplyGuard failure blocks all tool calls by design (fail
  closed) — operationally severe, deliberate.

## Threat model summary

SupplyGuard assumes the AI agent may act accidentally or adversarially:
introducing third-party software, executing ephemeral packages, weakening
checksum verification, altering CI dependencies, bypassing manifest controls,
or delegating risky behavior to another agent. The full threat model is
[`docs/SPEC.md` §3](docs/SPEC.md).

Trust boundaries:

- **Inside:** the SupplyGuard policy engine, its configuration files
  (including the operator's local policy rules), the audit log, and the human
  answering an approval prompt. Local policy is always authoritative; external
  intelligence can only tighten a decision, never weaken it.
- **Boundary:** the Pi `tool_call` interception point. Decisions
  (`ALLOW`/`WARN`/`ASK`/`DENY`, most restrictive wins) are enforced before
  tool execution for `DENY`.
- **Outside:** the agent, tool input, project files, and external providers —
  all treated as untrusted input to policy evaluation.

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
| Manifest snapshots / indirect manifest mutation detection | **Enforced** (M3, retrospective — see limits above) |
| Vendor detection / drift; ask-once vendor model | **Enforced** (M3) |
| Dependency justification required before a trust decision | **Enforced** (M4) |
| Release cooldown, per profile, with a proxy-outage posture | **Enforced** (M4) |
| Scoped one-shot overrides, reason-required in paranoid | **Enforced** (M4) |
| Typosquatting / reposquatting against a trust corpus | **Enforced** (M5; Unicode lookalikes M14) |
| Vulnerability metadata (OSV), per severity and profile | **Enforced** (M6) |
| Socket artifact scans and provider health, via the CLI | **Enforced** (M7) |
| Socket Firewall (protected fetch), Socket manifest scan | Out of scope by decision (2026-10-14) |
| `curl \| sh` / `wget \| sh` denial, in every profile | **Enforced** (M8; split download→execute M12) |
| GitHub Actions full-SHA pinning; `docker://` digests; network events | **Enforced** (M8, M12) |
| Writes gated before they land (manifests, `vendor/`, `node_modules/`) | **Enforced** (M9; file tools since D21) |
| Tool input revised after the gate | Detected and audited, not prevented (M9) |
| Local content scan of dependency source before approval | **Enforced** (M10) |
| Hermetic builds and paranoid vendor quarantine | **Enforced** (M11) |
| npm adapter: commands, lockfiles, lifecycle scripts | **Enforced** (M13) |
| Incident replay corpus; live contract tests | **In CI** (M14) |
| Local policy rules (operator-defined, offline, tighten-only) | **Enforced** (M15) |
| Sensitive-data rails: exfiltration denied, sensitive reads asked | **Enforced** (M16; bypasses D24/D25 closed in M18) |
| Execution classifier, paranoid-only, ASK-capped | **Experimental** (M17; live endpoint unproven until the `LIVE=1` canary runs) |
| Adversarial bypass corpus for rules and rails | **In CI** (M18) |

## Supply-chain policy for this project itself

`pi-supplyguard` holds itself to the standard it enforces: one pinned runtime
dependency (`yaml@2.9.0`), exact-pinned dev dependencies, no floating
versions in `dependencies`/`devDependencies` (the optional host
peerDependency is deliberately `*`, see KNOWN-GAPS §4), Node built-ins
preferred, and human review required for any dependency change. See
[`README.md`](README.md) and [`AGENTS.md`](AGENTS.md).
