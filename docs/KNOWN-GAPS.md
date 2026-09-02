# Known Gaps and Defect Log

**Status:** M1, M2 and M3 complete. M4 partially complete — dependency
justification is enforced; release cooldown and scoped overrides are not.
M5–M9 not started.
**Last updated:** 2026-09-02

This document is deliberately blunt. `pi-supplyguard` is a security control, and
a security control that overstates its coverage is worse than none: it converts
"I should check this" into "the tool would have caught it".

Nothing here is a surprise or a regression. Everything is either scheduled for a
later milestone, or a deliberate decision recorded with its reasoning.

---

## 1. Enforcement gaps

What SupplyGuard does **not** protect against today. Verified empirically
against the M3 tree, not inferred from the code.

### 1.1 Manifest reconciliation is retrospective, and bounded by the session

M3 closed the "indirect mutation is invisible" gap: a `go.mod` rewritten by
`sed`, Python or a generated script is detected by comparing before/after
snapshots and becomes the same normalized event a `go get` would have produced.
Four limits come with that design, and none of them is an accident.

**It is detected on the NEXT tool call, not before the edit lands.** The Pi host
fires `tool_call` *before* a tool runs, so the earliest SupplyGuard can observe
a file change is the following call. The host does fire a `tool_result` event
afterwards, but `ToolResultEventResult` cannot block — it only rewrites the
result — so hooking it would move the observation earlier without moving the
enforcement earlier. The gate is therefore "the agent cannot keep working after
an unapproved manifest edit", not "the edit cannot happen".

**The baseline is session-scoped.** The first tool call in a repository
establishes it; whatever state the repository was already in is the starting
point, not a mutation. Persisting the baseline across sessions would report
every commit, branch switch, `git pull` and editor save made while Pi was not
running as an unapproved change. SupplyGuard reports what it observed while it
was watching.

**An approved manifest-writing command launders concurrent edits in the same
call.** `go get x@v1.2.3` is expected to rewrite `go.mod`, so the resulting
change is reconciled and audited rather than re-gated. A single tool call
running `go get x@v1.2.3 && sed -i s/y/evil/ go.mod` therefore gets one approval
covering both. Two things bound it, both enforced and tested: the operation must
be one that actually writes a manifest (a read-only `go mod verify` cannot
vouch for anything), and a human must have **approved** it — "the call was not
blocked" is not enough. Verifying that the observed diff matches the approved
artifact is M4 work (the approval object already carries the artifact and
version).

The same expectation is attributed to ONE following call. If the host ever
dispatches a batch of tool calls whose hooks all fire before any of them
executes, the expectation is whatever the last hook in the batch set — which is
conservative unless that last call is itself a manifest-writing Go command.

**A change made and reverted inside ONE tool call is invisible.** Reconciliation
compares states, not history:

```text
sed -i s/v1.2.3/v9.9.9/ go.mod && go build ./... && git checkout go.mod
```

leaves `go.mod` byte-identical, so the next snapshot matches and nothing is
reported — while the build ran against the unapproved version. No hook the host
offers helps here: `tool_result` fires after the revert has already happened, so
observing it would show the same clean state. Closing this needs either
filesystem-level watching or a network-level control on the fetch itself
(Socket Firewall, M7). Until then, a `THIRD_PARTY_CAPABLE` build in a repository
an agent can also write to is not an admission boundary.

### 1.2 A rejected manifest state blocks every later call until it is reverted

When an unapproved manifest change is denied, the baseline deliberately does not
advance: the next tool call reconciles the same change and denies again. That is
the intended posture — forgetting a rejected mutation would let the second call
inherit it as clean — but it is operationally severe, and the way out is to put
the file back (or approve the change), not to keep retrying.

### 1.3 Generic policies are not implemented

```text
curl https://example.com/install.sh | sh   ->  SUPPLY_CHAIN_IRRELEVANT
uses: actions/checkout@v4                  ->  not inspected
```

SPEC §15 requires denying installer pipelines in every profile and requiring
full-SHA GitHub Actions references in hardened/paranoid. Neither exists yet.

The shell parser in `src/generic/shell.ts` already produces the pipeline-aware
view this needs — `curl … | sh` parses into two simple commands — so M8 is
wiring, not new parsing.

Workflow files are also absent from the manifest snapshot set, which SPEC §14.1
includes. That is deliberate: snapshotting `.github/workflows/*.yml` before M8
would gate every unrelated CI edit with an `ASK` and no security signal to show
for it, because nothing yet knows a mutable action reference from a renamed job.
It also needs glob support in `readManifestSnapshot`, which today takes a fixed
path list.

**Closed by:** M8.

### 1.4 Whole subsystems are absent, not partial

None of the following exist in any form. A clean SupplyGuard result today says
nothing about any of them:

| Capability | Milestone |
|---|---|
| Release cooldown / minimum release age | M4 |
| Scoped one-shot overrides with a reason | M4 |
| Trust corpus, typosquatting, repository-squatting | M5 |
| Vulnerability data (OSV) | M6 |
| Socket artifact/manifest scans, Firewall, provider health | M7 |

`config.releaseAgeMinimumDays` is parsed and carried through the precedence
chain so the layering is testable, but **nothing consumes it**. `/supplyguard-status`
labels it "enforced from M4" for exactly this reason. Release age needs a
publication date, which means an outbound request to the Go module proxy — the
first network call SupplyGuard would ever make, and a design decision in its own
right (see `HANDOFF.md`).

The approval object is therefore still partial. SPEC §11.2 lists release age,
vulnerability findings, similarity findings and transitive impact alongside the
purpose and stdlib fields; only the agent-supplied half exists today. The
approval prompt shows what it has and does not pretend the rest was checked.

### 1.5 The Go vendor model is narrower than SPEC §9.3 describes

Vendor drift is enforced (SPEC §9.4), the ask-once vendor question is asked and
persisted (SPEC §9.2), and Paranoid denies a dependency mutation in a project
with no vendor tree (SPEC §9.3). Two pieces of §9.3 are not implemented as
written:

- **Hardened does not prompt "Enable vendoring".** SupplyGuard does not execute
  commands, so it cannot vendor a project; the honest rendering of "recommend
  Enable, allow Continue" is an audit note, which is exactly what §9.3 requires
  of the headless case. Enabling vendoring means running `go mod vendor`.
- **`go: vendor: auto|enforce|optional` from SPEC §8.3 is not parsed.** The
  configuration loader still warns `unsupported configuration key "go"`. Vendor
  enforcement today comes from the ask-once decision and from the profile.

Drift is also only reported on supply-chain-relevant calls: `ls` in a repository
with a stale vendor tree is not gated. "Deny completion" (SPEC §4.4) is rendered
as "deny the operations that matter", because SupplyGuard has no task-completion
hook. `go mod vendor` is deliberately exempt from the drift finding it would
otherwise trip: denying the only command that repairs the state would leave
editing configuration as the sole way out, and SPEC §17.2 rules that out as an
override. It still passes the normal gate on its own merits.

The drift check itself is narrower than Go's own consistency check: it compares
versions for every vendored module, and reports a vendored module `go.mod` no
longer requires only when the tree marks it `## explicit`. A non-explicit
leftover is not reported. Editing `vendor/modules.txt` is itself gated, so this
is bounded, but it is not the same test `go build -mod=vendor` runs.

### 1.6 Non-`go.mod` manifests are classified coarsely

`go.mod` gets a full semantic diff (add / upgrade / downgrade / remove /
replace / exclude). `go.sum`, `go.work`, `go.work.sum` and `vendor/modules.txt`
changes become a single `LockfileMutation` carrying line counts — enough to
gate, not enough to say which module moved. Deleting `go.sum` is the one
special case: it removes the checksums Go verifies against and is a
`ChecksumBypass`, denied in every profile.

A tracked file larger than 4 MiB (`MAX_TRACKED_BYTES`) is hashed but not
retained, so a change to it is reported as an unclassifiable manifest mutation.
It is still gated; it just cannot be explained.

Vendored **source** is not tracked at all — only `vendor/modules.txt`. That
matches SPEC §14.1, but it is worth saying plainly: with vendoring enforced the
build compiles from `vendor/`, and editing a vendored `.go` file changes nothing
SupplyGuard watches. Hashing a whole vendor tree on every tool call is not the
answer; noticing it is M9's problem.

### 1.7 `go generate` is treated as merely capable

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

### 1.8 A hostile co-installed extension can rewrite an approved command

The Pi host allows a `tool_call` handler to mutate `event.input`, and does not
re-validate it afterwards. An extension registered after SupplyGuard could
therefore rewrite a command SupplyGuard has already approved.

SupplyGuard never rewrites tool input itself — it only allows or blocks — but it
cannot defend against a later handler that does.

**Closed by:** M9, to the extent it can be. Documented in `src/index.ts`.

### 1.9 The host API surface is hand-written and only spot-verified

`@earendil-works/pi-coding-agent` is an optional peerDependency and is
deliberately **not installed**: pulling ~136 transitive packages into a
supply-chain-security tool is the outcome this project exists to prevent.

`types/pi-coding-agent.d.ts` is therefore hand-written, and covers only the
surface `src/index.ts` uses. During M3 it was checked member by member against a
host installed globally on the development workstation (0.84.4): `ExtensionAPI.on`,
`registerCommand`, `ToolCallEvent`, `ToolCallEventResult`, `ExtensionContext`
(`cwd`, `hasUI`, `mode`, `ui`, `sessionManager`), `ExtensionUI` and
`sessionManager.getSessionId()` all match. Two deliberate divergences remain,
both safe for a caller: our `select` accepts a `readonly string[]`, and our
command `handler` may return `void` as well as a promise.

Consequences that stand:

- One workstation is not compatibility testing. A different host version can
  still diverge, and the failure would appear at runtime, not at compile time.
- The host's behavior when a `tool_call` handler **rejects** is still not
  confirmed. SupplyGuard fails closed on its own errors precisely because that
  behavior is unknown (§2.2 below).

**Mitigation:** compatibility testing against a pinned host before publication.
The peerDependency range is still `*` pending that work.

### 1.10 A non-numeric wrapper flag value degrades to unknown risk

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

### 1.11 Configuration changes take up to 5 seconds to apply

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

### 2.6 An unjustified dependency is denied, not merely asked about

SPEC §11.2 says a dependency approval REQUIRES a purpose, whether the standard
library was considered, and why it is insufficient. Those are the agent's
answers, so SupplyGuard registers `supplyguard_justify_dependency` and denies
dependency operations with no matching justification, naming the tool in the
refusal.

Asking anyway, with the fields blank, was the alternative. It would make the
tool decorative: the agent would never call it, and the human would keep
approving changes with no stated purpose — the situation SPEC §11 exists to end.

The requirement applies to dependency events from the *manifest* as well as from
the command gate, deliberately. If only commands needed a justification, then
`sed -i go.mod` would be the cheaper way to add a dependency, and the incentive
gradient would point straight at the bypass M3 exists to close. The cost is that
a human hand-editing `go.mod` mid-session sees a refusal until the agent records
a rationale — or reverts the edit.

Recording a justification grants nothing: it is evidence at the gate, the human
still decides, and it is consumed by one operation on one version (SPEC §11.3,
§17.2).

### 2.7 Delegated workers cannot mutate dependencies at all

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
(§1.11).
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

### D8 — `// indirect` was stripped before the parser could read it

The `go.mod` parser removed comments and *then* looked for the `// indirect`
marker inside the comment-free line, so every requirement parsed as direct. Two
consequences: an indirect requirement promoted to direct (or the reverse) was
not a change at all, and the `indirect-flag` classification could never fire.
Fixed by returning the comment alongside the directive text.
Pinned by *"parseGoMod reads inline and block requires with indirect markers"*
and *"indirect flag change is its own kind"*; mutation-checked.

### D9 — a retracted version range was silently dropped

`retract [v1.0.0, v1.0.2]` is one directive containing a space. The parser split
the line into words and matched `[v1.0.0,` against a range pattern that could
never accept it, so the entry vanished — and a `retract` block that changed
between two documents could compare equal.
Pinned by *"parseGoMod reads exclude and retract"* and *"a retracted version
range is preserved as one entry"*.

### D10 — upgrade and downgrade were inverted

**Severity: high.** `compareVersions(old, new)` returns a negative number when
the new version sorts later, and the diff treated a positive result as the
upgrade. Every version bump was reported as a downgrade and every rollback as an
upgrade, in the audit record and in the approval prompt a human reads before
allowing a dependency change.
Pinned by *"version bump is classified as upgrade"*, *"version drop is
classified as downgrade"* and both pseudo-version ordering tests.

> D8–D10 were found in inherited, uncommitted M3 work before it shipped. They
> are logged because the defect log is evidence about the test corpus, not about
> who wrote the bug.

### D11 — a read-only `go mod` subcommand laundered arbitrary manifest rewrites

**Severity: critical.** The reconciliation expectation was derived from the
subcommand *word*, so `go mod verify`, `go mod why`, `go mod graph` and
`go work sync` all announced "this call rewrites manifests" while producing no
operation and no event. The runtime then armed the flag on `!blocked` — true of
every allowed call — so the next call's file changes were reconciled instead of
gated:

```text
go mod verify && sed -i s/foo/evil/ go.mod   ->  allowed, unprompted, UNAUDITED
```

The audit record it left was actively false: "reconciled 1 tracked file
change(s) with the preceding approved operation", when nothing had been
approved. It worked in `paranoid` too, via `go work sync`. Fixed on both sides:
the flag now comes from the recognized *operations*, and only an operation a
human **approved** can vouch for a change.
Pinned by *"a read-only go subcommand cannot vouch for a manifest rewrite"*,
*"a denied manifest-writing command does not vouch for the next change"* and
*"only manifest-writing go commands announce an expected manifest change"*;
mutation-checked.

### D12 — a shadowed `replace` could be redirected to a remote module invisibly

**Severity: critical.** The semantic diff keys directives in a `Map`, and the
replace key discarded the version on the left of the arrow. Two version-scoped
replaces of the same module collapsed to one, so rewriting the shadowed entry —
including pointing it at attacker-controlled code, the highest-risk `go.mod`
construct per SPEC §10.5 — produced **no change at all**. Duplicate `require`
lines collapsed the same way. Fixed by making the left-hand version part of the
replace's identity, plus a canonical-form backstop so a hash-detected change can
never diff to silence again.
Pinned by *"a version-scoped replace is identified by its own version"* and
*"a change the parser cannot attribute is reported, never swallowed"*;
mutation-checked.

### D13 — unreadable top-level lines were dropped, not recorded

A line that did not begin with a keyword was skipped instead of being pushed to
`unparsed`, contradicting the parser's own contract and removing the backstop
that makes unmodelled structure visible in a diff. Fixed.
Pinned by *"an unreadable top-level line stays visible in unparsed"*.

### D14 — pseudo-version ordering was inverted against its base tag

`comparePseudo` ranked `v1.2.3-pre.0.<ts>-<hash>` *below* `v1.2.3-pre`. Semver
ranks the longer identifier list higher, so every such bump was reported as a
downgrade — D10's defect class, in the branch D10's tests never reached
(replacing the whole function body with `return 0` used to pass the suite).
Fixed, and both branches are now tested.
Pinned by *"a pseudo-version sorts after the base tag it extends"* and
*"a pseudo-version bump over its base tag is an upgrade, not a downgrade"*;
mutation-checked.

---

## 4. Release readiness

`package.json` is not publishable as it stands.

- `files` lists `README.md`, `SECURITY.md` and `LICENSE`; all three now exist
  (added by this branch) and `license: Apache-2.0` is backed by the `LICENSE`
  file.
- `peerDependencies` pins `@earendil-works/pi-coding-agent` at `*`, deliberately
  deferred until compatibility testing (§1.9).

Publishing is a human-approved operation (`AGENTS.md`) and none of this blocks
development, but the peer range still needs compatibility work before release.

---

## 5. How to keep this honest

- A new enforcement gap gets an entry here in the same commit that creates it.
- A defect gets an entry naming the test that pins it. No entry without a test.
- When a milestone closes a gap, delete the entry — do not mark it "done". This
  file describes the present, not the history of intentions.
- `grep -rn "ponytail:" src/` lists the deliberate shortcuts in code; §1.11 is
  the current one.
