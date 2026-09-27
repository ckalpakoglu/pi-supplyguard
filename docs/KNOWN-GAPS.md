# Known Gaps and Defect Log

**Status:** M1–M6, M8 and M9 complete. M7 complete for scans and provider
health; Socket Firewall deliberately not implemented (§1.5).
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
enforcement earlier. SupplyGuard hooks `tool_result` only to learn that an
approved manifest writer has actually run (below). The gate is therefore "the
agent cannot keep working after an unapproved manifest edit", not "the edit
cannot happen".

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

The expectation arms on the approved call's own `tool_result`, not at hook time.
omp runs every `tool_call` hook of one assistant message before executing any
of them, and Pi can execute tools in parallel, so an expectation set at hook
time would be overwritten by the next hook in the batch before the writer ran.
Once armed, the next call's reconciliation consumes it. A writer that was
blocked by another extension, denied at omp's approval gate or aborted produces
no `tool_result` and vouches for nothing: whatever changed the manifest is
re-gated. So is a write that lands after its call's `tool_result` — an `async`
bash job or a named service still writing after the tool returned. That is
conservative: a human is asked again, nothing is laundered. A host that
supplies no call id keeps the one-following-call semantics.

**A change made and reverted inside ONE tool call leaves nothing to
reconcile** — reconciliation compares states, not history. M9 narrowed this
from the other end: a command that can be READ as writing a tracked manifest is
now gated *before* it runs, so

```text
sed -i s/v1.2.3/v9.9.9/ go.mod && go build ./... && git checkout go.mod
```

never executes. Redirections (including into a heredoc), in-place editors,
`cp`/`mv`/`tee`/`truncate` and `git checkout`/`restore` of a tracked path are
all covered, through wrappers and nesting.

What remains uncovered is the shape a command cannot be read for:

```text
python3 rewrite_gomod.py        # the write is inside the script
./generated-tool                # so is this one
```

Those still rely on snapshot reconciliation, and so a script that substitutes
and reverts within one tool call is still invisible. Closing THAT needs
filesystem-level watching or a network-level control on the fetch (Socket
Firewall, which §1.5 records as not implemented).

### 1.2 A rejected manifest state blocks every later call until it is reverted

When an unapproved manifest change is denied, the baseline deliberately does not
advance: the next tool call reconciles the same change and denies again. That is
the intended posture — forgetting a rejected mutation would let the second call
inherit it as clean — but it is operationally severe, and the way out is to put
the file back (or approve the change), not to keep retrying.

### 1.3 Generic policy coverage stops at the shapes SPEC 15 names

Installer pipelines and GitHub Actions references are enforced. Three edges are
not, and each is a deliberate line rather than an oversight:

- **A download and its execution in two steps.** `curl -o i.sh …; sh i.sh` is a
  `NetworkRequirement`, not a pipeline: the file is on disk to be read, which is
  exactly the distinction SPEC §15.2 draws. Whether the agent then reads it is
  not something SupplyGuard can see.
- **Container image digests.** `uses: docker://alpine:3` is treated as
  out-of-scope rather than as a mutable reference. Pinning image digests is the
  same idea applied to a different registry, and it belongs with M9.
- **Mutable references already committed** are reported as audit notes on gated
  operations, not as a gate. Denying every command in a repository whose
  workflows predate SupplyGuard would make the profile unusable on arrival;
  *changing* a workflow to introduce one is what produces an event.

Workflow files now join the manifest snapshot set (SPEC §14.1), through a
deliberately small glob: one `*` in the final path segment, which covers
`.github/workflows/*.yml` and nothing more ambitious.

### 1.4 Identity analysis protects only what the corpus names

Typo- and repository-squatting analysis (SPEC §12) is enforced, and its limits
are structural rather than temporary:

- **With no corpus it does nothing.** SPEC §12.6 requires exactly that: the tool
  has no way to know which `foo/bar` is the real one, and a version that guessed
  would produce confident nonsense about ownership. Paranoid says so in the
  approval prompt; no profile denies for the absence alone.
- **The corpus is not an allow-list.** A module that is absent is not
  "untrusted"; it is simply not something a typo could be aimed at. An attacker
  registering a name that resembles nothing protected is invisible to this
  check, and always will be.
- **The thresholds are the SPEC's own starting points** (0.08 / 0.15 / 0.25) and
  it says they "must be calibrated against true-positive and false-positive
  corpora before stable release". `test/core/identity.test.ts` carries a
  negative corpus of real, unrelated modules; it is small.
- **The variant is restricted Damerau-Levenshtein** (optimal string alignment):
  adjacent transpositions cost one edit, a transposed pair edited again does
  not. That is the typo people actually make, and the unrestricted algorithm
  costs more for cases nobody types.
- **No Unicode or homoglyph normalization.** SPEC §12.3 lists it as optional
  future work, and a Cyrillic `о` in a module path would pass this check today.

### 1.5 Socket is the CLI only: no Firewall, and no manifest scan

Human decision, 2026-09-02: M7 integrates the **Socket CLI**
(`socket package score`), not Socket Firewall. What that leaves undone is
load-bearing, because SPEC §13.4 makes Firewall mandatory for Paranoid:

- **No protected fetch.** SupplyGuard can tell you a package looks bad *before*
  you fetch it; it cannot stop the fetch at the network layer. Paranoid
  therefore does NOT meet SPEC §13.4 in full, and SPEC §4.4's "Socket Firewall:
  Mandatory" row is unimplemented. The ask-once Hardened Firewall prompt
  (SPEC §13.3) does not exist either — the ask-once machinery it would use is
  built and in service for the vendor question.
- **No manifest/project scan.** SPEC §13.4 requires one after a dependency graph
  mutation. Only per-artifact scoring is wired.

**`socket package score` requires a Socket API token.** The CLI ships a public
token, but it is used only by the `socket npm`/`pnpm`/`yarn` wrappers, not by
the scan commands, which check `hasDefaultApiToken()` and fail with "This
command requires a Socket API token for access". Without `SOCKET_CLI_API_TOKEN`
or `socket login`, every artifact scan is therefore `unavailable` — which
**warns** in standard and hardened and **denies** in paranoid. In other words:

> Paranoid cannot admit a new dependency unless the Socket CLI is installed
> *and* authenticated.

That is SPEC §13.4 working as designed, not a defect, but it is the kind of
thing that gets a profile switched off if it arrives as a surprise.

**Never exercised against the real CLI.** The command, the purl form and the
`{ok, data:{self:{score,alerts}}}` document shape were read out of the published
`socket@1.1.163` bundle, and every behaviour is tested against an injected
runner — no test starts a process. A CLI change would surface as `unavailable`
(the conservative direction) rather than as a wrong verdict, because an
unrecognized document is never read as clean.

The approval object is still partial. SPEC §11.2 lists vulnerability findings,
similarity findings and transitive impact alongside the purpose, stdlib and
release-age fields; the first three arrive with M5 and M6. The approval prompt
shows what it has and does not pretend the rest was checked.

### 1.6 The outbound lookups are network requests, with everything that implies

Release cooldown (SPEC §11.1) needs a publication date and vulnerability data
(SPEC §16) needs an advisory database, so SupplyGuard makes two kinds of
outbound request: the Go module proxy and OSV. Both follow the same rules.

- **A public service learns which modules a repository takes on.** `GOPRIVATE`
  and `GONOPROXY` are honored *before* a request is built, and
  `GOPROXY=off`/`direct` disable both lookups entirely. A module covered by any
  of those is reported as "not applicable" and never queried — which also means
  its age and its advisories are never checked, in any profile.
- **An outage is not a bypass.** Standard and hardened warn; paranoid denies
  and, per SPEC §17.3, does *not* offer a one-shot override for it. The way out
  is to restore access or change the profile deliberately.
- **Answers are cached per process, never persisted**, and both lookups run only
  for artifacts already heading for a human gate — a build command costs no
  request. Advisories do change, unlike a publication date, so a long-running
  session can hold a stale clean answer.
- **Neither has been exercised against the live service in CI**: the test suite
  is verified to make zero network calls, and every behaviour is covered with an
  injected `fetch`. The OSV request shape is pinned by a test, not by a
  contract test against osv.dev.
- **Severity depends on what the database says.** OSV entries without a
  `database_specific.severity` or a scored CVSS vector are `unknown`, which
  paranoid denies and the other profiles ask about. No CVSS vector is *computed*
  from its metrics: a vector with no attached score yields `unknown` rather than
  a guess.

### 1.7 The Go vendor model is narrower than SPEC §9.3 describes

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

### 1.8 Non-`go.mod` manifests are classified coarsely

`go.mod` gets a full semantic diff (add / upgrade / downgrade / remove /
replace / exclude). `go.sum`, `go.work`, `go.work.sum` and `vendor/modules.txt`
changes become a single `LockfileMutation` carrying line counts — enough to
gate, not enough to say which module moved. Deleting `go.sum` is the one
special case: it removes the checksums Go verifies against and is a
`ChecksumBypass`, denied in every profile.

A tracked file larger than 4 MiB (`MAX_TRACKED_BYTES`) is hashed but not
retained, so a change to it is reported as an unclassifiable manifest mutation.
It is still gated; it just cannot be explained.

Vendored **source** is not snapshotted, only `vendor/modules.txt`, which is
what SPEC §14.1 lists. With vendoring enforced the build compiles from
`vendor/`, so editing a vendored `.go` file changes nothing the snapshot
watches. Direct writes into the tree are therefore gated by **command shape**
instead: the Go adapter exposes `vendor/` as a write-guard prefix, and a
`sed -i vendor/…`, `cp … vendor/…` or redirection into it is a `VendorDrift`
mutation before it runs. `go mod vendor` names no file operand, so the
legitimate refresher is not caught. Hashing a whole vendor tree on every tool
call remains the "obvious" fix and a bad one: thousands of files per call, to
catch a case an attacker reaches only after already having write access to the
repository. What the prefix gate still does not see is a write made from
inside a script the command line does not name.

### 1.9 `go generate` asks in every profile

```text
go generate ./...  ->  ThirdPartyExecution (ask / ask / ask)
```

`go generate` runs the `//go:generate` directives declared in source —
arbitrary commands, in any checked-out or vendored file, and a classic shape is
`//go:generate go run tool@latest`: a floating-version install and execute the
command gate never sees, because it happens inside the tool. Formerly this
section recorded the operation as merely capable; raised 2026-09-27.

The known cost: repositories that generate routinely now answer a prompt per
`go generate`. That is the same friction class as an exact-version `go get`,
and the alternative — treating execution of arbitrary declared commands like
`go build` — is the hole the raise closed.

### 1.10 A hostile co-installed extension can rewrite an approved command

The Pi host allows a `tool_call` handler to mutate `event.input`, and does not
re-validate it afterwards. omp's form is a handler returning a revised `input`:
the last one wins, handlers do not see each other's revisions, and omp
re-resolves its own approval tier on the revised input but does not re-run
extension hooks. Either way, an extension registered after SupplyGuard could
rewrite a command SupplyGuard has already approved.

SupplyGuard never rewrites tool input itself — it only allows or blocks — but it
cannot defend against a later handler that does.

**Not closable in either host — but no longer silent.** The `tool_result`
event carries the input the tool actually received, so SupplyGuard hashes the
input it evaluated and compares: a revision after the gate produces a warning
and an `input-revision` audit record (hash prefixes only, never contents). A
benign formatter extension can trip it, which is exactly why the answer is a
warning and not a block. Hosts whose result event carries no input (omp's may
not) cannot be compared at all.

### 1.11 The host API surface is hand-written and only spot-verified

`@earendil-works/pi-coding-agent` is an optional peerDependency and is
deliberately **not installed**: pulling ~136 transitive packages into a
supply-chain-security tool is the outcome this project exists to prevent.

`types/pi-coding-agent.d.ts` is therefore hand-written, and covers only the
surface `src/index.ts` uses. It is checked member by member against both hosts
installed on the development workstation: Pi 0.84.4 and omp 18.3.4.
`ExtensionAPI.on` (`tool_call`, `tool_result`), `registerCommand`,
`registerTool`, `ToolCallEvent`, `ToolCallEventResult`, `ToolResultEvent`
(`toolName`, `toolCallId`, `isError`), `ExtensionContext` (`cwd`, `hasUI`,
`mode`, `ui`, `sessionManager`), `ExtensionUI` and
`sessionManager.getSessionId()` match in both. `ToolDefinition.loadMode` and
`ToolDefinition.approval` are omp-only fields that Pi ignores. omp loads the
package through `package.json#omp.extensions` and rewrites the
`@earendil-works/pi-coding-agent` specifier to its own host copy; every import
of it is type-only. Two deliberate divergences remain, both safe for a caller:
our `select` accepts a `readonly string[]`, and our command `handler` may return
`void` as well as a promise.

Consequences that stand:

- One workstation is not compatibility testing. A different host version can
  still diverge, and the failure would appear at runtime, not at compile time.
- The host's behavior when a `tool_call` handler **rejects** is still not
  confirmed. SupplyGuard fails closed on its own errors precisely because that
  behavior is unknown (§2.2 below).

**Mitigation:** compatibility testing against a pinned host before publication.
The peerDependency range is still `*` pending that work.

### 1.12 A non-numeric wrapper flag value degrades to unknown risk

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

### 1.13 Configuration changes take up to 5 seconds to apply

`.supplyguard.yaml` is re-read when the cached copy is older than
`CONFIG_TTL_MS` (5s). Staleness is bounded and can only ever withhold a
*tightening*, because configuration layers may never weaken — a stale copy is
never more permissive than the file on disk. Marked `ponytail:` in
`src/index.ts`; switch to mtime comparison only if the reload ever shows up in a
profile.

### 1.14 omp-specific surfaces

omp (oh-my-pi) exposes tools Pi does not. What each one gets:

**Inspected before execution.**

- `bash` `env` and `cwd`: the call is analyzed as `NAME='value'` lines and
  `cd 'dir'` followed by the command, so `{ command: "go build ./...", env:
  { GOSUMDB: "off" } }` is the checksum bypass it is. Values reach the parser
  only, never prompts or audit records. Pinned by `test/core/omp-host.test.ts`.
- `write` to `proc://<id>`: the content is stdin for a running process (a
  shell service), so it is analyzed as a command. A `write` to any other path is
  a file write, never a command.
- Nested `xd://` device dispatch emits its own `tool_call`.
- `tool.<name>()` from an `eval` cell emits its own `tool_call`: verified end to
  end with `tool.bash({ command: "go get github.com/google/uuid@latest" })`,
  which was denied and audited.

**Retrospective only (§1.1 reconciliation on the next call).**

- `eval` cells themselves, including `%pip install` and `%bun add`: the code is
  not a shell command and is not parsed.
- `write`, `edit`, `ast_edit`, `lsp` and `xd://` device writes to tracked
  files. Human decision: parity with Pi's file tools, no pre-landing gate.
- Patches merged back from isolated `task` subagents: reconciled on the Chief's
  next call.
- `debug` launches: unclassified, like any non-shell tool.

omp subagents run headless, so a dependency `ASK` in a subagent fails closed
and the Chief-only dependency rule (§2.8) holds.

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

### 2.7 An override cannot lift an invariant, whatever the human answers

SPEC §17.2 scopes an override to one policy, one artifact, one version, one
execution. SupplyGuard adds a fourth constraint the SPEC implies but does not
spell out: a finding has to *opt in* to being waivable, and only the release
cooldown does. A floating version, a checksum bypass, a missing justification or
paranoid's vendoring requirement produce denials that no prompt offers to lift —
the override is never even displayed.

The guard lives in `applyHumanOverride`, not at the call site, because a call
site can be edited by someone who has not read §17.2.

### 2.8 Delegated workers cannot mutate dependencies at all

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
(§1.13).
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

### D15 — a heredoc swallowed the redirection on its own line

The tokenizer, on seeing `<<`, skipped straight to the heredoc delimiter — which
also consumed the rest of that line, where the redirection lives:

```text
cat <<'EOF' > go.mod        ->  was: no write recorded
module evil/replacement
EOF
```

Harmless while redirections were discarded anyway; a live bypass the moment M9
started gating writes to tracked manifests, and the most natural way to write a
whole file from a shell. Fixed by scanning the remainder of the line for
redirections before skipping the body.
Pinned by *"a heredoc redirected into a manifest is a write"*; mutation-checked.

### D16 — exempting `go` from the manifest-write gate opened a hole

The write detector skipped commands whose tool was `go`, reasoning that the Go
adapter already gates them. It does — for `go mod edit` and friends, which name
no file operand and were never matched here anyway. What the exemption actually
bought was a way through:

```text
go list -m all > go.sum     ->  was: not a write
```

Found by mutation testing: deleting the exemption broke no test, which is what
prompted asking what it was for. Removed.
Pinned by *"go's own subcommands are not matched, yet go is not a way
through"*.

### D14 — pseudo-version ordering was inverted against its base tag

`comparePseudo` ranked `v1.2.3-pre.0.<ts>-<hash>` *below* `v1.2.3-pre`. Semver
ranks the longer identifier list higher, so every such bump was reported as a
downgrade — D10's defect class, in the branch D10's tests never reached
(replacing the whole function body with `return 0` used to pass the suite).
Fixed, and both branches are now tested.
Pinned by *"a pseudo-version sorts after the base tag it extends"* and
*"a pseudo-version bump over its base tag is an upgrade, not a downgrade"*;
mutation-checked.

### D17 — nested shells and declaration builtins hid checksum bypasses and manifest writes

**Severity: high.** `unwrap()` returned early for `sh -c` / `eval` without a
command, dropping the segment's prefix assignments, and `parseShell()` then had
no command to attach the segment's redirections to. Declaration builtins were
not parsed at all:

```text
GOSUMDB=off sh -c 'go build ./...'   ->  was: no ChecksumBypass
export GOSUMDB=off; go build ./...   ->  was: no ChecksumBypass
sh -c 'echo x' > go.mod              ->  was: no write recorded
eval "go build" > go.sum             ->  was: no write recorded
```

Fixed by keeping the assignments on an empty-argv command when a nested script
is handed off, parsing `NAME=value` arguments of `export`, `declare`,
`typeset`, `readonly` and `local`, and emitting an empty-argv carrier for a
segment's redirections when no command survives unwrapping.
Pinned by *"a checksum bypass is caught however it is spelled"* and
*"wrappers and nesting do not hide the write"*; both fail without the fix.

### D18 — the Socket runner refused SupplyGuard's own flags, so Socket never ran

**Severity: medium (fail-closed, not a bypass).** The runner checked every
argument with `isSafeArgument`, which refuses anything starting with `-`. The
health check passes `--version` and the score query passes `--json`, so both
were refused before any process started:

```text
socket --version                          ->  was: "refused to pass an unsafe argument"
socket package score pkg:golang/… --json  ->  was: never run
```

Even with the CLI installed, Socket contributed nothing in standard and
hardened, and paranoid denied every new trust decision on a provider failure
that was really SupplyGuard's own. The suite missed it because every Socket
test injected a runner, so the real argument check never ran. Found while
testing SupplyGuard under Pi, where the prompt showed the misleading reason
instead of "not installed". Fixed by letting SupplyGuard's own flags through,
matched exactly (`CLI_FLAGS`); every other argument is still checked.
Pinned by *"an installed Socket CLI passes its health check and scores an
artifact"* (fails without the fix) and *"only SupplyGuard's own flags pass the
runner, and only exactly"*.

### D19 — an alert repeated in Socket's transitive section was counted twice

**Severity: low (reporting only).** `socket package score --json` repeats the
package's own alerts under `transitively`, and the parser appended both
sections unfiltered. Against the real CLI (1.1.180) the approval prompt read:

```text
Socket reported 4 alert(s) … networkAccess, usesEval, networkAccess, usesEval
```

No decision changed — the worst severity was the same — but a prompt that
double-counts teaches the human to skim it. Fixed by reporting a name at a
given severity once; the same name at a different severity stays a separate
alert, so the worst severity is never lost. Found while testing D18's fix
against the installed CLI.
Pinned by *"an alert repeated in the transitive section is reported once"*.

---

## 4. Release readiness

`package.json` is not publishable as it stands.

- `files` lists `README.md`, `SECURITY.md` and `LICENSE`; all three now exist
  (added by this branch) and `license: Apache-2.0` is backed by the `LICENSE`
  file.
- `peerDependencies` pins `@earendil-works/pi-coding-agent` at `*`, deliberately
  deferred until compatibility testing (§1.11).

Publishing is a human-approved operation (`AGENTS.md`) and none of this blocks
development, but the peer range still needs compatibility work before release.

---

## 5. How to keep this honest

- A new enforcement gap gets an entry here in the same commit that creates it.
- A defect gets an entry naming the test that pins it. No entry without a test.
- When a milestone closes a gap, delete the entry — do not mark it "done". This
  file describes the present, not the history of intentions.
- `grep -rn "ponytail:" src/` lists the deliberate shortcuts in code; §1.13 is
  the current one.
