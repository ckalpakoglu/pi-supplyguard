# Zero-Day Hardening Plan — M10–M14

Branch: `feature/zero-day-hardening`. Status: **plan, approved for design — not
implemented.** This document extends `docs/SPEC.md`, it does not replace it;
where the two disagree during implementation, stop and ask.

## 0. What this plan claims, precisely

"Prevents zero-day supply-chain attacks" is not a testable claim. This is:

> After M10–M14, a dependency whose malicious content has never been seen by
> any database cannot enter a guarded build **silently**: it must pass a
> content scan whose findings are shown to a human, land in a quarantined
> vendor tree, and survive a hermetic build with no network — or be blocked.

Three things that statement deliberately does not promise:

1. **Runtime exfiltration by approved code.** Once approved code runs with
   network access, no prompt-time tool can help; that needs an OS-level egress
   control (recommend running guarded sessions under one; out of scope here).
2. **A human who approves everything.** Evidence packs and cooldowns reduce
   rubber-stamping; they cannot abolish it. Approval fatigue is tracked as a
   first-class design metric (M10).
3. **Ecosystems beyond Go and npm.** npm lands in M13 because agent-driven
   incidents concentrate there (postinstall scripts). Python/Cargo remain
   unmapped.

## 1. Threat classes and their controls

The honest version of the roadmap: which attack survives which control.

| # | Class | Example | Defeated by | Status |
|---|---|---|---|---|
| A | Novel malware in a fresh version of a plausible dependency | event-stream, ua-parser-js | cooldown + **content scan before approval** (M10) + vendor quarantine + hermetic build (M11) | cooldown ✓; rest missing |
| B | Typosquat / dependency confusion, novel name | `github.com/google/uuid`-lookalike nobody protects | auto-generated corpus (M14), homoglyph normalization (M14), Jev name/context check (M10) | corpus manual-only; homoglyph gap §1.4 |
| C | Compromised release moment | tag pushed same day as malware | release age ✓ + maintainer/repo signal (M14) | age ✓; signals missing |
| D | Build-time execution/exfil by dependency code | `init()`, cgo, generate directives | **hermetic build after mutation** (M11): enforced vendor, `GOPROXY=off`, no exec of unscanned code; Jev source scan flags egress/exec shapes (M10) | vendoring enforced; hermetic gate missing |
| E | Agent-injected malice through the shell | the whole bypass corpus | command gate ✓ + fetch→execute correlation (M12) + out-of-band write watch (M12) | gate ✓; correlation/watch missing |
| F | CI compromise | mutable `uses:`, `docker://` tags | Actions pinning ✓ + **image digest pinning** (M12) | refs ✓; digests §1.3 |
| G | Host-layer (co-extension, eval cells) | input rewrite, `%pip install` | audit trail ✓ (1.10, 1.14); prevention impossible in-host | documented, accepted |

Classes A–D are the "zero-day" core: their common property is that **no
database knows the answer**, so the only honest defenses are content
inspection, time, and blast-radius reduction. That is what M10–M11 buy.

## 2. Design pillars

### P1 — Evidence before approval (M10)

The approval prompt today shows agent-written prose plus database verdicts.
For class A that is decoration. The prompt must carry **evidence about the
artifacts' content**, and an approval without an evidence pack must not be
offerable.

- **Jev provider** per the recorded decision (KNOWN-GAPS §1.15): default off,
  `experimental` flag in status/audit, additive-only, ASK cap while
  experimental, public modules only, explanation text is untrusted display
  data. New: `src/providers/jev/`, config `jev.enabled`.
- **`go.sum` semantic diff** (§1.8): which module moved, in which direction,
  surfaced in the approval object — the human approves *what actually
  changed*, not "go.mod ±1 line".
- **Evidence-pack approval**: when an artifact heads for a human, the prompt
  assembles justification + OSV + Socket + similarity + release age + Jev
  findings (files/lines when available) + go.sum delta. A dependency event
  with **no content evidence at all** (provider off, no vendor tree) is
  `ASK` with an explicit "uninspected content" banner in hardened, `DENY` in
  paranoid — today paranoid can approve uninspected code if Socket is healthy,
  which defeats class A.
- **Approval fatigue metric**: count ASKs per session in audit; a profile
  option `approval bundling` (one prompt listing the session's pending
  dependency operations, each with its evidence) ships behind a flag and is
  measured before it becomes default.

### P2 — Blast radius (M11)

Assume the human approves wrong. What limits the damage?

- **Vendor quarantine**: with vendoring enforced, a newly added dependency is
  `vendorState = quarantined` until scanned (M10 provider) — builds from
  vendor proceed, but `paranoid` requires `scanned` before any build/test, and
  `hardened` warns. The invariant: **uninspected third-party code never
  executes in a guarded build in paranoid.**
- **Hermetic post-mutation gate**: after `dependencyGraphDirty`, the first
  build-shaped command must run hermetically. SupplyGuard does not execute
  commands, so the gate is: synthesize `GOFLAGS=-mod=vendor GOPROXY=off` as
  **required prefix assignments** for that call (the parser already treats
  them as checksum-relevant state); a build that would fetch (`-mod=mod`, no
  vendor tree) is gated. This turns "approved the wrong thing" into "approved
  the wrong thing, offline".
- **Digest-everything**: `go.sum` pins content (Go's own guarantee, which we
  never weaken); Actions get digest pinning in M12; the same principle, not a
  new mechanism.

### P3 — Close the enumerated bypasses (M12)

- **Fetch→execute correlation**: `NetworkRequirement` events are remembered
  per session; executing a file whose path matches a remembered download
  (`sh x.sh` from §1.3's deliberate edge) raises a `SecurityBypass` finding.
  Session state, no new host surface.
- **Out-of-band write watch**: `fs.watch` on the repo root (node built-in, no
  dependency) for tracked paths, attributing writes that land **outside** any
  tool call to an attribution-gap audit record. Catches the
  `python3 rewrite.py` class at detection time (still not prevention — the
  script already ran — but the next tool call no longer needs to be the tripwire).
- **`docker://` digest pinning** in the generic Actions layer (§1.3).
- **`GOPRIVATE` scope validation**: a scoped pattern is compared against the
  module being added; a scope wider than the user's own orgs warns in
  hardened, denies in paranoid (narrows deliberate §2.1 honestly).

### P4 — npm adapter (M13)

`package.json` / `package-lock.json` semantic diff; `npm|pnpm|yarn|npx install`
commands; **lifecycle scripts are the threat model**: a new/changed
`postinstall`/`preinstall` in the dependency graph is a `ToolInstall`-class
event gated before `npm ci` runs, with the script body shown in the evidence
pack. Without this, class A on npm is entirely ungated.

### P5 — Freshness and calibration (M14)

- **Live contract tests** behind `LIVE=1` (skipped by default; run in a weekly
  CI job): real proxy, real OSV, real Socket. D18 happened because every test
  injected its runner; this is the structural fix.
- **Corpus tooling**: `supplyguard-trust init` — generate the trust corpus
  from `go.mod` + `go list -m all` so §1.4's dormant flagship actually has
  input by default.
- **Homoglyph/Unicode normalization** in identity analysis.
- **Incident replay corpus**: real attacks encoded as tests — event-stream,
  ua-parser-js, colours.js, node-ipc, the `go generate` install shape — replayed
  end-to-end against the runtime. A control that fails a replay fails the milestone.
- **Maintainer/repo signals** (opt-in provider): new-maintainer, repo-transfer,
  archive-resurrection patterns feeding class C.

## 3. Milestones, ordered

Each milestone: `npm run check` green, positive+negative tests per AGENTS.md,
KNOWN-GAPS updated in the same commit, live Pi+omp smoke for the host surface.

| M | Delivers | Key files | Acceptance |
|---|---|---|---|
| M10 | Jev provider, go.sum semantics, evidence-pack approvals, uninspected-content gates, fatigue metric | `src/providers/jev/`, `src/adapters/go/modfile.ts`, `src/core/approval.ts`, `src/core/engine.ts` | A class-A synthetic (fixture module with planted exfil) is flagged or banner-denied in paranoid; prompt shows file/line |
| M11 | Quarantine vendor state, hermetic post-mutation gate | `src/adapters/go/project.ts`, `src/adapters/go/index.ts`, `src/generic/shell.ts` (prefix synthesis) | After mutation, a fetching build is gated in paranoid; `GOPROXY=off` build passes |
| M12 | Fetch→execute correlation, out-of-band watch, docker digests, GOPRIVATE scoping | `src/generic/installers.ts`, `src/generic/github-actions.ts`, `src/index.ts` | §1.3's two-step edge closes; a scripted manifest write is attributed |
| M13 | npm adapter | `src/adapters/npm/` | A postinstall-carrying lockfile change is gated with the script body shown; replay corpus npm cases pass |
| M14 | Live contract tests, corpus tooling, homoglyph, replay corpus, signals | `test/live/`, `src/analyzers/`, CI | Replays green; corpus generated from a real repo in one command |

Sequencing rationale: M10/M11 target the zero-day core (classes A/D) first;
M12 is small and closes named holes; M13 widens coverage where incidents
actually happen; M14 keeps every earlier claim honest over time.

## 4. Non-goals, restated as engineering constraints

- No new runtime dependencies (node built-ins only; Jev is `fetch`).
- No fifth decision; external evidence stays additive-only (invariant 12).
- No weakening of checksum verification for any integration, ever.
- No auto-approval path for headless workers (§2.8 stands).
- Nothing in this plan relies on the agent's cooperation: evidence packs are
  assembled from artifacts, not from agent-supplied prose.

## 5. Falsification

This plan is wrong if, after M10–M14:

1. A replay from the incident corpus passes the gate silently; or
2. paranoid can execute uninspected third-party code; or
3. the median ASK-per-session rises (fatigue metric) — more prompts would mean
   the evidence work failed and the gate is training rubber-stamping.

Each has a test or metric named above. That is the difference between this
plan and a promise.
