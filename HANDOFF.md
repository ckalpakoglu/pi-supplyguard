# HANDOFF

**Last updated:** 2026-09-02
**Branch:** `feature/m3-manifest-engine` → merged to `main`
**State:** `npm run check` green — typecheck clean, full suite passing.

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
| M7 | Socket integration: artifact/manifest scans, health, Firewall | **Next** |
| M8 | Generic policies: GitHub Actions SHA pinning, `curl\|sh`, network events | Complete |
| M9 | Adversarial hardening: indirect mutation, headless, Chief/worker parity, bypass corpus | Not started |

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
  Hardened Socket Firewall opt-in (SPEC §13.3) is the second, in M7.
- **Dependency mutations are Chief-only** (human decision, 2026-09-01, in
  `AGENTS.md`). A headless worker's `ASK` fails closed. Do not add a bypass.
- **The Pi host package is deliberately not installed.** `types/pi-coding-agent.d.ts`
  is hand-written; see KNOWN-GAPS §1.9 for what has and has not been verified.

## What M6 needs

`docs/SPEC.md` §16 is short and the shape is already in place: `EngineContext`
takes an `externalEvidence` provider whose findings can only tighten
(`withExternalEvidence`), and M4 established both the "adapter answers a
question about an artifact" hook and the network posture that goes with it.

OSV (`https://api.osv.dev/v1/query`) takes an ecosystem, a package name and a
version and needs no credentials. The questions M6 has to answer are the ones
M4 answered for the proxy, repeated: which modules must never be sent (the same
`GOPRIVATE` rule), what an unavailable provider means per profile (SPEC §16:
"unknown is never silently equivalent to clean in Paranoid"), and whether a
finding is overridable — a known CRITICAL vulnerability should not be, and
SPEC §4.4 says High is "Deny / override" in hardened and "Deny / exceptional
override" in paranoid.

## Verification

```bash
npm run check     # tsc --noEmit + node --test over test/**/*.test.ts
```

There is no linter and no formatter in the toolchain; `npm run check` is the
whole gate. Security-relevant logic is expected to be mutation-checked by hand
(break it, confirm the suite fails, put it back) — the defect log in
`docs/KNOWN-GAPS.md` §3 records which entries were verified that way.
