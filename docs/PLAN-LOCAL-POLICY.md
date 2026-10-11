# PLAN — Local policy: deterministic rules, sensitive-data rails, execution classifier

Status: design agreed 2026-10-11. **M15 done** (`4b9cf41`, simplified in
`4b4279a`; SPEC §8.5, KNOWN-GAPS §1.18). M16–M18 not started. This document
is the roadmap. The canonical design conversation is summarized in §1; the
milestones in §3 are the build order. Follow `docs/SPEC.md` where this plan is
ambiguous, and amend SPEC (not this file) when a milestone lands.

Branch: `feature/local-policy-engine`, cut from `feature/zero-day-hardening`
at `a37395f` (M10–M14 + D20/D21 fixes; `main` does not contain those yet).

---

## 0. What this plan claims, precisely

Three capabilities, one principle: **deterministic rules are the floor, the
classifier is only ever a ceiling-raiser.**

1. A **local policy engine**: operator-authored rules (match → decision)
   enforced offline, in every profile, before execution. Today every
   deterministic rule is hard-coded in adapters; the operator has no voice.
2. **Sensitive-data rails**: built-in, non-removable rules — never *send*
   sensitive files anywhere, gate *access* to them by shape, tiered by
   egress-coupling. Available in every profile; they cost nothing and need no
   network.
3. An **execution classifier** (Jev/CLEF-shaped, behind a provider
   interface): a probabilistic second opinion on *tool executions* — the
   agent's own commands — available only at `paranoid`. This is deliberately
   NOT a supply-chain verdict: zero-day malicious *dependencies* remain
   Socket's job (paranoid already fails closed on unscanned artifacts). The
   classifier owns the class nothing owns today: malicious *execution*
   (obfuscated `python -c`, reverse shells in local scripts,
   `find / -delete`).

Explicitly not claimed: a sandbox, a guarantee, an allow-list mechanism, or a
replacement for any existing gate. Every escalation ends at a human.

## 1. Design decisions (already taken — do not relitigate per milestone)

Each of these was a policy position, settled in design discussion:

| # | Decision | Rationale |
|---|---|---|
| D1 | Rules may decide `warn \| ask \| deny` only; `allow` is rejected at load | An allow-rule is an exception primitive that could weaken built-in gates; violates the tighten-only lattice (SPEC §8.2). Suppressing a warn is a scoped, audited, one-shot prompt decision. |
| D2 | Rules compose by most-restrictive-wins with each other, profile baselines, adapter events, and external evidence | One combinator (`core/decisions.ts`), no new decision paths. |
| D3 | Malformed rule → loud warn + ignore that rule + status line + audit config-notice | Ignoring loses protection but never opens a hole (rules only tighten). Visibility over brittleness. |
| D4 | Rail 1 (never-send) is override-proof: human approval authorizes *execution*, never *upload* | Overrides waive denials for running code, not for data egress. A sensitive file that cannot be scanned yields "decide without classifier evidence". |
| D5 | Classifier verdicts are capped at `ask`, even in paranoid, while experimental | Probabilistic; a false-positive auto-deny bricks the most fragile profile. Cap lifts later by threshold change once precision is observed. |
| D6 | Classifier unavailability fails *soft*: warn + audit + local policy stands | Commands are not dependency trust decisions; paranoid's offline-vendored build/test promise (SPEC §9.3) must survive. Deliberate deviation from the Socket-required rule; document in KNOWN-GAPS. |
| D7 | Classifier availability is profile-gated: effective profile `paranoid` + enabled + key, else the code path does not load | Tighten-only extension of the profile ordering; no latency or egress below paranoid. Dynamic import stays (deleting the provider is non-fatal). |
| D8 | Matcher set is closed and tiny: `command`, `argsContain`, `toolName`, `writePrefix`, `readPrefix`, `pathGlob` | A policy DSL is an attack surface. Shapes and paths, not file content; no regex in v1. |
| D9 | One parser: rules match on the same wrapper-stripped parsed argv the adapters use (`sh -c 'git push --force'` matches like the bare command) | No second convention to drift or bypass. |
| D10 | Never-send list and rail-2 tiers are built-in rules, extend-only via config union (global ∪ project) | Operators add paths; nobody removes the floor. |

## 2. Architecture

One insertion point; everything downstream is existing machinery:

```text
tool_call
→ snapshot/reconcile (existing, SPEC §14)
→ adapters: classification + events (existing)
→ LOCAL RULES (new): built-ins + operator rules match call shape and paths
  → findings, origin "policy", carrying rule id + reason
→ mostRestrictive: profile baselines ∪ events ∪ rules ∪ external evidence
→ ASK prompts the human (headless: deny) / DENY blocks / audit (existing)
```

Consequences that come for free: approval prompts show the rule id and
reason; `/supplyguard-log` records them; headless sessions fail closed on
`ask`; audit redaction applies. The classifier folds in through the existing
external-evidence slot — it is the last, most expensive, least trusted input.

New code homes:

```text
src/policy/           the engine (directory exists, empty, reserved)
  rules.ts            rule schema, load-time validation, built-ins
  match.ts            matchers over parsed argv / tool input / paths
  fold.ts             findings construction (origin "policy")
src/providers/classifier/  execution-classifier provider interface
src/providers/jev/         first implementation (classify + analyze-file)
```

`src/core/engine.ts` gains the fold; `src/core/config.ts` gains the
`policies` and `sensitive` keys with tighten-only layering. No adapter learns
about rules; no rule learns about ecosystems.

## 3. Milestones, ordered

Numbering continues from M14. Each milestone: `npm run check` green,
positive + negative tests per rule (AGENTS.md), KNOWN-GAPS updated in the
same commit, live Pi smoke for the host surface.

### M15 — Local policy engine (operator rules)

Scope:

- Rule schema + validation (`warn|ask|deny` only; unknown keys warn+ignore).
  Layers concatenate: no dedupe by id (dedupe let a project rule displace a
  global one) and no rule cap (matching is microseconds per rule).
- Matchers D8/D9: `command` on wrapper-stripped argv[0]; `argsContain`
  substring on any arg; `toolName`; `writePrefix`/`readPrefix` over shell
  operands AND file-tool path inputs (the `sensitive-writes.ts` semantics);
  `pathGlob`.
- Engine fold + audit fields (rule id, reason, source layer: global/project).
- `/supplyguard-status`: active rules listed with their layer; config-notice
  for rejected rules.
- Config layering: global ∪ project, project may only add.

Acceptance (tests):

- Contract table: each decision value gates as its lattice position says.
- Negative: `ls`, `git status`, plain reads — no rule matches, no findings,
  not audited (invariant 9 shape).
- Wrapper/composition: `sudo git push --force`, `sh -c '…'`, `env X=y kubectl
  delete …`, heredoc-written protected prefix — all match.
- Layering: project adds to global; a project rule with a global rule's id
  cannot displace it.
- Malformed rule ignored loudly; `decision: allow` rejected at load.
- Headless: rule `ask` → deny (worker parity).
- Path normalization: `./infra/x`, `infra/../infra/x`, absolute paths inside
  the repo all match `writePrefix: infra/`.

Docs: SPEC amendment "Local policy rules"; KNOWN-GAPS entry (bounds: no
allow, no content matching, no regex, no per-session rules).

### M16 — Sensitive-data rails (built-ins, all profiles)

Scope:

- **Rail 2 — access tiers** (built-in rules; D10):

  | Shape | standard | hardened/paranoid |
  |---|---|---|
  | egress-coupled read (`curl -d @.env`, `scp ~/.aws/… h:`, request body from a sensitive path) | Deny | Deny |
  | plain read into tool output (`cat .env`, `less ~/.netrc`) | Ask | Ask |
  | metadata only (`ls ~/.ssh`) | Allow | Allow |

  Operand-shape matching only: `ssh`/`git push` using keys internally name no
  sensitive operand and are untouched.
- **Rail 1 — never-send corpus** (built-in, extend-only): `.env*`, `*.pem`,
  `*.key`, `id_rsa*`, `~/.ssh/**`, `~/.gnupg/**`, `~/.aws/**`, `~/.netrc`,
  `*.kdbx`, `*secret*`, `*credential*`, `.tfvars`, binaries, size budget.
  Enforced against every present and future sender (classifier stage 2, any
  later provider) through one shared predicate, not per-provider copies.
- **Rail 3 — hygiene**: redaction of `token=`, `Bearer `, `sk-`, long hex
  runs from anything that leaves the machine; shared with M17.
- File-tool parity: `edit`/`write`/`read` path arguments tier the same way
  shell operands do.

Acceptance (tests):

- Positive/negative per tier row; egress-coupling detection via operand +
  command shape (`curl`/`wget`/`scp`/`rsync`/`POST`-body redirections).
- `git push` over ssh untouched (no operand names a key).
- Config extension merges (union), cannot remove built-ins.
- Never-send predicate unit-tested against the corpus; enforced even when no
  classifier exists (it gates nothing then, but the predicate is the M17
  dependency and must exist independently).

Docs: SPEC "Sensitive-data rails"; KNOWN-GAPS entry (bounds: operand-shape,
not content; symlink traversal documented as out of scope v1).

### M17 — Execution classifier (paranoid-only)

Scope:

- Provider interface `src/providers/classifier/`:
  `classifyCommand(command) → {harmful, reason?} | {error}` and
  `analyzeFile(text) → {malicious} | {error}`; Jev implementation behind the
  existing dynamic-import discipline (never a dependency).
- Trigger (D7): effective profile `paranoid` + `jev.enabled` + key in env
  (`TYPESAFE_API_KEY`/`JEV_API_KEY`); classification ≠
  `SUPPLY_CHAIN_IRRELEVANT`; invariant 9 preserved — harmless calls never
  leave the machine, testable.
- Stage 1 — command triage: redacted command text (rail 3), char budget,
  per-session cache keyed by hash.
- Stage 2 — whole file, triggered by: stage-1 `harmful` high; command names
  a local script to execute; **about to execute a file downloaded this
  session** (the M12 correlation set — always escalates, no triage).
  Rail 1 checked first: sensitive file → refuse, prompt says "not scannable
  (sensitive path); decide without classifier evidence" (D4). Text-only,
  size budget.
- Verdict mapping (D5/D6): harmful ≥ 0.7 → `ask` finding with p and file
  evidence in the one existing prompt; below threshold → nothing, ever — a
  benign verdict never weakens a local gate; error/timeout → `warn`
  ("vouches for nothing"), audit records the attempt.
- One prompt: command verdict + file verdict + local findings together.

Acceptance (tests, injected transport — no network in the suite):

- Paranoid-only: standard/hardened never invoke the provider.
- Harmful → ask finding reaches the prompt; benign → decision identical to
  no-classifier baseline (byte-for-byte audit comparison).
- Unavailable/timeout → warn + local decision unchanged.
- Harmless command never sent (invariant 9 test).
- Redaction: `token=…`/`Bearer …` never appear in the outbound payload.
- Downloaded-then-executed always escalates to stage 2.
- Sensitive file: stage 2 refused with the honest prompt line; approval does
  not authorize upload.
- Cache: repeat commands cost one call.

Docs: SPEC "Execution classifier (experimental)"; KNOWN-GAPS entry: fail-soft
deviation from Socket-required (D6), ASK cap (D5), probabilistic bounds.

### M18 — Adversarial hardening and calibration

Scope:

- Bypass corpus extensions (the falsification habit from M9/M14): rules vs
  wrapper/nested shells; heredoc into a rule-protected prefix; path
  normalization attacks against `writePrefix`; rule-matching TOCTOU notes.
- `LIVE=1` contract test for the classifier endpoint (self-skips without a
  key) — the D18 lesson applied on day one: every other test injects the
  transport, so the live path needs its own canary.
- Fatigue metrics: classifier prompts per session surfaced in
  `/supplyguard-status` next to the existing approval-fatigue number.
- Threshold calibration notes from audit data (no auto-tuning).
- SPEC consolidation: threat model gains "malicious tool execution by the
  agent (prompt injection or model error)"; rules/rails/classifier sections
  finalized.

## 4. Non-goals, restated as engineering constraints

- No `allow` rules, no exception grammar, no time/condition logic (v1).
- No file-content matching in rules; content judgment belongs to the
  classifier behind its rails.
- No regex matchers; glob + prefix + exact only.
- No new runtime dependencies; the classifier is a provider behind dynamic
  import, deletable without trace (existing Jev discipline).
- No per-ecosystem rule behavior: rules see shapes and paths, adapters see
  ecosystems.
- Nothing sends anything below `paranoid`; nothing sends a rail-1 path ever.

## 5. Falsification

A control in this plan is not done until a test proves it can fail:

- **Rules**: a wrapper-wrapped or path-normalized shape that escapes a
  matching rule is a defect (M15 tests, M18 corpus).
- **Rails**: any egress-coupled sensitive read that passes untiered, or any
  approved upload of a never-send path, is a defect (M16).
- **Classifier**: any benign verdict that changes a decision, any harmless
  command that leaves the machine, any redaction miss, any hard dependence on
  provider availability below paranoid — each is a defect (M17).
- **Live path**: if the `LIVE=1` canary has never run against the real
  endpoint, the integration is unproven regardless of suite green (D18).

## 6. Sequencing and dependencies

```text
M15 (engine)  →  M16 (rails as built-in rules + never-send predicate)
                        ↓
              M17 (classifier; consumes rail 1 + rail 3)
                        ↓
              M18 (hardening, live canary, calibration)
```

M15 and M16 deliver standalone offline value in every profile even if M17 is
never built; M17 without M16 is forbidden (a classifier without its
deterministic floor violates the plan's opening principle).
