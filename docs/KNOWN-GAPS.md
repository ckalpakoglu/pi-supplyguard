# Known Gaps and Defect Log

**Status:** M1 and M2 complete. M3–M9 not started.
**Last updated:** 2026-09-01

This document is deliberately blunt. `pi-supplyguard` is a security control, and
a security control that overstates its coverage is worse than none: it converts
"I should check this" into "the tool would have caught it".

Nothing here is a surprise or a regression. Everything is either scheduled for a
later milestone, or a deliberate decision recorded with its reasoning.

---

## 1. Enforcement gaps

What SupplyGuard does **not** protect against today. Verified empirically
against `c4d8de3`, not inferred from the code.

### 1.1 Indirect manifest mutation is invisible — the largest gap

Command interception is not a filesystem boundary. SPEC §14 says so explicitly,
and it is still true:

```text
sed -i s/v1.0.0/v9.9.9/ go.mod    ->  SUPPLY_CHAIN_IRRELEVANT
python3 rewrite_gomod.py          ->  SUPPLY_CHAIN_IRRELEVANT
```

An agent that cannot run `go get` can still rewrite `go.mod` with any text
editing tool, and SupplyGuard will not notice. The gate covers the Go command
surface, nothing more.

**Closed by:** M3 — before/after manifest snapshots and semantic reconciliation
(SPEC §14). Until M3 lands, treat the command gate as one control among several,
not as an admission boundary.

### 1.2 Generic policies are not implemented

```text
curl https://example.com/install.sh | sh   ->  SUPPLY_CHAIN_IRRELEVANT
uses: actions/checkout@v4                  ->  not inspected
```

SPEC §15 requires denying installer pipelines in every profile and requiring
full-SHA GitHub Actions references in hardened/paranoid. Neither exists yet.

The shell parser in `src/generic/shell.ts` already produces the pipeline-aware
view this needs — `curl … | sh` parses into two simple commands — so M8 is
wiring, not new parsing.

**Closed by:** M8.

### 1.3 Whole subsystems are absent, not partial

None of the following exist in any form. A clean SupplyGuard result today says
nothing about any of them:

| Capability | Milestone |
|---|---|
| Vendor state, drift detection, `vendorState` transitions | M3 |
| Release cooldown / minimum release age | M4 |
| Scoped one-shot overrides, dependency justification | M4 |
| Trust corpus, typosquatting, repository-squatting | M5 |
| Vulnerability data (OSV) | M6 |
| Socket artifact/manifest scans, Firewall, provider health | M7 |

`config.releaseAgeMinimumDays` is parsed and carried through the precedence
chain so the layering is testable, but **nothing consumes it**. `/supplyguard-status`
labels it "enforced from M4" for exactly this reason.

### 1.4 `go generate` is treated as merely capable

```text
go generate ./...  ->  THIRD_PARTY_CAPABLE
```

`go generate` executes arbitrary `//go:generate` directives found in source. It
is arguably closer to `ThirdPartyExecution` than to `go build`. It is currently
classified with the other build-shaped subcommands, which means allow / allow /
warn across the profiles.

**Not yet scheduled.** Raising it is a one-line change in
`CAPABLE_SUBCOMMANDS`; the reason it has not been made is that no one has
assessed the false-positive cost on repositories that generate routinely.

### 1.5 A hostile co-installed extension can rewrite an approved command

The Pi host allows a `tool_call` handler to mutate `event.input`, and does not
re-validate it afterwards. An extension registered after SupplyGuard could
therefore rewrite a command SupplyGuard has already approved.

SupplyGuard never rewrites tool input itself — it only allows or blocks — but it
cannot defend against a later handler that does.

**Closed by:** M9, to the extent it can be. Documented in `src/index.ts`.

### 1.6 The host API surface is hand-written and unverified

`@earendil-works/pi-coding-agent` is an optional peerDependency and is
deliberately **not installed**: pulling ~136 transitive packages into a
supply-chain-security tool is the outcome this project exists to prevent.

Consequences:

- `types/pi-coding-agent.d.ts` is hand-written from observed host behavior. If
  the real API diverges, the failure appears at runtime, not at compile time.
- The host's behavior when a `tool_call` handler **rejects** could not be
  confirmed locally. SupplyGuard fails closed on its own errors precisely
  because that behavior is unknown (§2.2 below).

**Mitigation:** compatibility testing against a pinned host before publication.
The peerDependency range is still `*` pending that work.

### 1.7 A non-numeric wrapper flag value degrades to unknown risk

```text
sudo -u root go get foo@latest  ->  UNKNOWN_RISK   (not a precise DENY)
```

Wrapper unwrapping consumes a separated *numeric* flag value (`nice -n 10`)
because a bare number is never a program name. A non-numeric value is left in
place deliberately: consuming it could swallow the real command and produce
silence. Here that leaves `root` in command position, so the `go` word lands in
an argument position and the safety net fires.

The result is conservative and correct — standard/hardened ask, paranoid denies
— but it is less precise than the `DENY` the same operation earns unwrapped.
Running `go` as another user is arguably worth flagging in its own right.

### 1.8 Audit records do not say *why* a command was unreadable

When `analyzeCommand` returns `UNKNOWN_RISK`, the reason ("command
substitution", "unrecognized wrapper") is computed but discarded: the
`EcosystemAdapter` contract returns `{ classification, events }` with no notes
channel. The audit record shows the classification and the profile baseline that
produced the decision, but not the specific trigger.

Marked `ponytail:` in `src/adapters/go/index.ts`. Natural to fix in M3, when the
adapter contract widens for `inspectFileMutation` anyway.

### 1.9 Configuration changes take up to 5 seconds to apply

`.supplyguard.yaml` is re-read when the cached copy is older than
`CONFIG_TTL_MS` (5s). Staleness is bounded and can only ever withhold a
*tightening*, because configuration layers may never weaken — a stale copy is
never more permissive than the file on disk. Marked `ponytail:` in
`src/index.ts`; switch to mtime comparison only if the reload ever shows up in a
profile.

---

## 2. Deliberate behaviors that can look like gaps

These are decisions, not oversights. Each has a test pinning it so it cannot be
"fixed" by accident.

### 2.1 Scoped `GOPRIVATE` is allowed

`GOPRIVATE=*` is denied — it disables checksum verification for everything. But
`GOPRIVATE=github.com/mycorp/*` is normal internal-module usage and is **not**
treated as a checksum bypass. Denying it would make SupplyGuard unusable in
exactly the organizations that most want it.

### 2.2 A SupplyGuard failure blocks every tool call

Both the engine and the Pi wiring layer fail closed: an internal error becomes a
`DENY`, not a pass-through. If SupplyGuard fails *persistently* — a broken
`HOME`, say — the session is effectively bricked, including `ls`.

That is the intended posture and it is consistent with SPEC §27's conservative
failure model, but it is operationally severe, so the error message tells the
operator to fix the underlying problem or disable the extension deliberately.
Disabling the plugin is explicitly **not** the normal override mechanism
(SPEC §17.2).

### 2.3 Heredoc bodies are not parsed as commands

```text
cat <<'EOF' > install.sh
go get foo@latest
EOF
```

This *writes* a script; it does not run one. Parsing the body would flag every
generated file as an execution. Writing an installer is caught when it is
executed, not when it is composed.

### 2.4 `go\ get` is not a bypass

An escaped space produces a single word naming a program called `go get`, which
does not exist. The shell fails before anything is fetched. This was originally
written as a bypass test and was wrong.

### 2.5 `go get module@none` is gated, not merely warned

Removing a requirement reduces third-party surface, and `DependencyRemove` has a
`warn` event baseline. But the *classification* is `THIRD_PARTY_MUTATION`
(`ask`), and the most restrictive wins — so removal still asks. It mutates the
dependency graph and runs the resolver, so gating it is correct.

### 2.6 Delegated workers cannot mutate dependencies at all

Human decision, 2026-09-01, recorded in `AGENTS.md`. A headless worker's `ASK`
fails closed, so the Chief performs dependency trust decisions with a human
present. This is enforcement working as designed, not a gap. Brokered or
pre-scoped worker approval is deferred to M4.

---

## 3. Defect log

Defects found during development, with the test that now pins each. Listed
because a security control's failure history is evidence about the quality of
its test corpus, and because "we found this by writing adversarial tests"
justifies continuing to write them.

### D1 — `bash -lc '...'` escaped the nested-script path (live bypass)

**Severity: high.** Nested-shell detection matched the flag `-c` exactly, so
combined forms slipped through with the script never parsed:

```text
bash -lc 'go get foo@latest'   ->  was: not analyzed
bash -xc 'go get foo@latest'   ->  was: not analyzed
```

A gate that catches `sh -c` but not `bash -lc` looks like it works. Fixed by
matching `/^-[a-z]*c[a-z]*$/`.
Pinned by *"nested interpreters are parsed, including combined flags"*.

### D2 — separated flag values were mis-consumed by wrapper stripping

```text
nice -n 10 go get foo@latest      ->  was: command resolved to "10"
timeout -k 5 30s go get foo@latest ->  was: command resolved to "30s"
```

Degraded to `UNKNOWN_RISK` via the safety net rather than a precise `DENY`.
Fixed by consuming a separated numeric flag value, and by looping the duration
drop for `timeout`.
Pinned by *"transparent wrappers are stripped"*.

### D3 — unreadable commands denied in every profile

The Go adapter synthesized a `SecurityBypass` event for an unreadable command.
That class has a `deny` baseline in all three profiles, which flattened the
`ask / ask / deny` gradation SPEC §5.1 requires for `UNKNOWN_RISK`. Fixed by
returning the classification alone and letting `CLASSIFICATION_BASELINE` do its
job.
Pinned by *"paranoid denies an unreadable command that standard merely gates"*.

### D4 — the Pi wiring layer could fail open

**Severity: high.** `evaluateToolCall` carefully converted its own failures into
a `DENY`, but `onToolCall` — repository resolution, config loading, session id —
was unguarded. A rejected handler is very likely treated by the host as "no
opinion", which would have turned a SupplyGuard crash into a silent policy
bypass. Fixed by extracting `handleToolCall` and wrapping it.
Pinned by *"a failure in the wiring layer blocks the call instead of passing it
through"*; mutation-checked.

### D5 — configuration was cached for the session's lifetime

Adding or tightening `.supplyguard.yaml` had no effect until Pi restarted. Not
exploitable — layers may only tighten — but surprising. Fixed with a 5s TTL
(§1.9).
Pinned by *"a project configuration added mid-session is picked up once the
cache expires"*; mutation-checked.

### D6 — two audit defects

`detectGitBranch` assumed an absolute `gitdir:` path in a `.git` file; git
permits a relative one (worktrees, submodules), which silently lost the branch.
`redact` turned a `Map`/`Set` into `{}`, indistinguishable from "there was
nothing here". Both fixed.

### D7 — the M1 skeleton shipped untested wiring

`src/index.ts` had no tests at all, including the stated invariant that
`/supplyguard-profile` may only tighten. Closed by `test/core/runtime.test.ts`,
mutation-checked.

---

## 4. Release readiness

`package.json` is not publishable as it stands.

- `files` lists `README.md`, `SECURITY.md` and `LICENSE`; all three now exist
  (added by this branch) and `license: Apache-2.0` is backed by the `LICENSE`
  file.
- `peerDependencies` pins `@earendil-works/pi-coding-agent` at `*`, deliberately
  deferred until compatibility testing (§1.6).

Publishing is a human-approved operation (`AGENTS.md`) and none of this blocks
development, but the peer range still needs compatibility work before release.

---

## 5. How to keep this honest

- A new enforcement gap gets an entry here in the same commit that creates it.
- A defect gets an entry naming the test that pins it. No entry without a test.
- When a milestone closes a gap, delete the entry — do not mark it "done". This
  file describes the present, not the history of intentions.
- `grep -rn "ponytail:" src/` lists the deliberate shortcuts in code; §1.8 and
  §1.9 are the current two.
