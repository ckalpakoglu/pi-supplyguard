# HANDOFF

**Last updated:** 2026-09-02
**Branch:** `feature/m3-manifest-engine` → merged to `main`
**State:** `npm run check` green — typecheck clean, full suite passing. The
suite is instrumented to make zero network calls and start zero processes.

All nine milestones are closed. What v1.0 still needs is in
"SPEC §25 audit" below.

This file is navigation for whoever picks the project up next. It does not
duplicate `docs/KNOWN-GAPS.md`, which is the authoritative record of what is
*not* enforced.

---

## Objective

`pi-supplyguard` is a Pi coding-agent extension that makes dependency, tooling,
build and CI supply-chain trust decisions explicit, reviewable, enforceable
before execution, and auditable. Go is the first ecosystem; the policy core is
ecosystem-agnostic so npm/Python arrive as adapters, not as engine changes.

## Authoritative sources, in order

1. `docs/SPEC.md` — canonical product and security design (v1.0).
2. `AGENTS.md` — working agreement, invariants, milestone order, review rules.
3. Repository code and tests — git and the filesystem are the truth about state.
4. `docs/KNOWN-GAPS.md` — enforcement gaps, deliberate decisions, defect log.
5. This file — orientation only.

## Milestones

| Milestone | Scope | State |
|---|---|---|
| M1 | Pi skeleton: `tool_call` hook, config, profiles, decisions, audit, UI | Complete |
| M2 | Go command gate: `go get/install/mod/env/run`, exact versions, GOSUMDB | Complete |
| M3 | Manifest engine: semantic `go.mod`/`go.sum` state, snapshots, vendor detection and drift | Complete |
| M4 | Human trust gate: dependency justification, approval object, scoped overrides, release cooldown | Complete |
| M5 | Identity protection: trust corpus, Damerau-Levenshtein, reposquatting | Complete |
| M6 | Vulnerability metadata: OSV, provider abstraction | Complete |
| M7 | Socket integration: artifact/manifest scans, health, Firewall | Scans + health complete; Firewall out of scope by decision |
| M8 | Generic policies: GitHub Actions SHA pinning, `curl\|sh`, network events | Complete |
| M9 | Adversarial hardening: indirect mutation, headless, Chief/worker parity, bypass corpus | Complete |

## Layout

```text
src/index.ts              Pi wiring: hook, commands, per-repo session state
src/core/engine.ts        the pipeline; ecosystem-agnostic by construction
src/core/decisions.ts     ALLOW<WARN<ASK<DENY; every combinator is monotone
src/core/profiles.ts      profile ordering + the SPEC §4.4 baseline tables
src/core/events.ts        normalized event model and tool-call classification
src/core/manifest.ts      sensitive-file snapshots and diffs (SPEC §14)
src/core/config.ts        path resolution and tighten-only layering (SPEC §8)
src/core/state.ts         remembered state, incl. ask-once project decisions
src/core/audit.ts         JSONL audit log and redaction (SPEC §18)
src/core/approval.ts      the human gate; the only producer of a grant
src/core/justification.ts the agent's rationale (SPEC 11.2); one-shot, in-memory
src/core/release-age.ts   the cooldown policy; the date comes from an adapter
src/core/trust.ts         the protected identity corpus; NOT an allow-list
src/core/vulnerability.ts severity policy; the database is an adapter's business
src/analyzers/            similarity and component-aware identity analysis
src/adapters/registry.ts  the adapter contract
src/adapters/go/          the only code that knows what `go get` means
src/adapters/go/proxy.ts  the ONLY outbound request; GOPRIVATE honored first
src/generic/            rules that belong to no ecosystem, registered as an adapter
src/generic/sensitive-writes.ts  manifest writes gated BEFORE they land (M9)
src/providers/socket/   the ONLY process SupplyGuard starts; env is allow-listed
src/generic/shell.ts      shell parser shared by command analysis
```

## Load-bearing design decisions

- **The engine never learns what a package manager is.** Adapters translate;
  the engine decides. An adapter can assert a floor (`minimumDecision`) that
  `mostRestrictive` folds in, so it can tighten and never weaken.
- **Everything fails closed.** Engine errors, wiring errors, headless `ASK`,
  unresolved `ASK`, adapter failures. `docs/KNOWN-GAPS.md` §2.2 records the
  operational cost of that, deliberately.
- **Reconciliation is retrospective.** Pi's `tool_call` hook runs *before* the
  tool; `tool_result` exists but cannot block. So an unapproved manifest edit is
  caught on the following tool call. A denied state does not advance the
  baseline, so it keeps being caught until the file is put back.
- **The manifest baseline is session-scoped, never persisted.** Persisting it
  would report every commit, pull and editor save made while Pi was not running
  as an unapproved mutation.
- **An approved manifest-writing command is not asked about twice.** Adapters
  set `expectsManifestChange` from the *recognized operation*, never from the
  command word, and the wiring layer arms it only when a human **approved** the
  call. Both halves were security defects once (D11); neither is decoration.
- **Vendor drift is derived from disk, not from a dirty flag.** `go.mod` versus
  `vendor/modules.txt` gives SPEC §9.4's semantics without state that a restart
  or an out-of-band edit could desynchronize.
- **Ask-once project questions are generic.** The core prompts, persists and
  audits an opaque id/value pair. Vendor mode (SPEC §9.2) is the first user; the
  Hardened Socket Firewall opt-in (SPEC §13.3) would be the second, if Firewall
  is ever implemented.
- **Dependency mutations are Chief-only** (human decision, 2026-09-01, in
  `AGENTS.md`). A headless worker's `ASK` fails closed. Do not add a bypass.
- **The Pi host package is deliberately not installed.** `types/pi-coding-agent.d.ts`
  is hand-written; see KNOWN-GAPS §1.9 for what has and has not been verified.

## SPEC §25 audit — what v1.0 still needs

The roadmap is finished; the v1.0 success criteria are not, and the gap is one
subsystem rather than a long tail. Fourteen of the seventeen criteria hold and
have tests:

| Criterion | State |
|---|---|
| `standard` is the default profile | Met |
| standard/hardened/paranoid decisions are contract-tested | Met |
| Existing Go vendor projects detected and preserved | Met |
| Paranoid blocks dependency mutation until vendoring is established | Met |
| Unversioned and `@latest` operations blocked | Met |
| `GOSUMDB=off` blocked | Met |
| Direct **and indirect** `go.mod`/`go.sum` changes become semantic events | Met |
| New dependencies/upgrades require human approval | Met |
| Release cooldown and scoped override behavior per profile | Met |
| Trust corpus enables component-aware typo/repository-squatting analysis | Met |
| Mutable GitHub Actions and installer pipelines enforced | Met |
| Paranoid fails closed on provider outage, vendored offline builds still work | Met |
| All security decisions and overrides auditable | Met |
| Chief and spawned workers receive identical enforcement | Met |
| The core remains ecosystem-independent | Met |
| **Hardened asks once whether to enable Socket Firewall** | **Not met** |
| **Paranoid requires Socket manifest evaluation and protected fetch** | **Partly** — artifact scanning only |

All three shortfalls are the same decision: M7 integrates the Socket CLI, not
Socket Firewall (`docs/KNOWN-GAPS.md` §1.5). Closing them means a protected
fetch path — proxy, registry or wrapper, capability-detected per SPEC §13.9 —
plus `socket scan create` for the manifest scan, plus the ask-once Hardened
prompt, for which the machinery already exists and is in service for the vendor
question.

Two other things stand between the current tree and a release:

- **`peerDependencies` still pins the host at `*`.** The hand-written
  declarations were checked member by member against 0.84.4 on one workstation
  (§1.11); that is not compatibility testing.
- **`socket package score` requires a Socket API token.** Worth knowing before
  anyone runs `paranoid`: without one, every artifact scan is unavailable, and
  paranoid denies new dependencies on that basis.

## Verification

```bash
npm run check     # tsc --noEmit + node --test over test/**/*.test.ts
```

There is no linter and no formatter in the toolchain; `npm run check` is the
whole gate. Security-relevant logic is expected to be mutation-checked by hand
(break it, confirm the suite fails, put it back) — the defect log in
`docs/KNOWN-GAPS.md` §3 records which entries were verified that way.
