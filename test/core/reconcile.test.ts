/**
 * End-to-end manifest reconciliation through the Pi wiring layer (SPEC 14, 23.2).
 *
 * `test/go/reconcile.test.ts` proves the Go adapter classifies a file change.
 * These tests prove the whole path works: a real repository on disk, the real
 * Go adapter, the real runtime, and the tool calls an agent would actually
 * make. This is the gap KNOWN-GAPS §1.1 described -- an agent that cannot run
 * `go get` rewriting `go.mod` with `sed` instead.
 */
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { createGoAdapter, VENDOR_MODE_DECISION } from "../../src/adapters/go/index.ts";
import { createAdapterRegistry } from "../../src/adapters/registry.ts";
import { createRuntime, type SupplyGuardRuntime } from "../../src/index.ts";

const tempRoots: string[] = [];

async function tempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  tempRoots.push(dir);
  return dir;
}

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

interface Recorder {
  readonly notices: string[];
  readonly prompts: string[];
  answer: string | undefined;
}

function recorder(answer?: string): Recorder {
  return { notices: [], prompts: [], answer };
}

function context(cwd: string, rec: Recorder, hasUI = true) {
  return {
    cwd,
    hasUI,
    mode: hasUI ? ("tui" as const) : ("print" as const),
    ui: {
      select: async (title: string) => {
        rec.prompts.push(title);
        return rec.answer;
      },
      confirm: async () => false,
      input: async () => undefined,
      notify: (message: string) => {
        rec.notices.push(message);
      },
    },
    sessionManager: { getSessionId: () => "session-1" },
  };
}

interface Harness {
  readonly runtime: SupplyGuardRuntime;
  readonly repo: string;
  readonly home: string;
  readonly rec: Recorder;
  /** Run one bash tool call; returns the block result, if any. */
  call(command: string): Promise<{ block?: boolean; reason?: string } | undefined>;
  write(path: string, content: string): Promise<void>;
  /** Record the agent-side justification SPEC 11.2 requires. */
  justify(module: string, version: string): Promise<void>;
}

const BASE_GO_MOD = `module example.com/app

go 1.22

require github.com/foo/bar v1.2.3
`;

async function harness(
  options: { answer?: string; hasUI?: boolean; profile?: string } = {},
): Promise<Harness> {
  const repo = await tempDir("supplyguard-repo-");
  const home = await tempDir("supplyguard-home-");
  const rec = recorder(options.answer);

  if (options.profile !== undefined) {
    await writeFile(join(repo, ".supplyguard.yaml"), `version: 1\nprofile: ${options.profile}\n`);
  }

  const runtime = createRuntime({
    home,
    env: {},
    // No test may reach the network; release-age behaviour is covered by
    // test/core/release-age.test.ts with an injected proxy.
    registry: createAdapterRegistry([createGoAdapter({ env: { GOPROXY: "off" } })]),
  });

  const ctx = context(repo, rec, options.hasUI ?? true);
  return {
    runtime,
    repo,
    home,
    rec,
    call: (command) =>
      runtime.onToolCall({ toolName: "bash", toolCallId: "1", input: { command } }, ctx),
    write: (path, content) => writeFile(join(repo, path), content),
    justify: async (module, version) => {
      const result = await runtime.justifyTool(
        {
          module,
          version,
          purpose: "needed for the feature under test",
          stdlibConsidered: true,
          stdlibInsufficientReason: "the standard library has no equivalent",
        },
        ctx,
      );
      assert.notEqual(result.isError, true, JSON.stringify(result.content));
    },
  };
}

// ---------------------------------------------------------------------------
// The gap M3 exists to close.
// ---------------------------------------------------------------------------

test("a dependency added with sed is caught on the next tool call", async () => {
  const h = await harness({ answer: "Deny" });
  await h.write("go.mod", BASE_GO_MOD);

  // Establishes the baseline. `sed` is invisible to the command gate.
  assert.equal(await h.call("sed -i s/v1.2.3/v9.9.9/ go.mod"), undefined);

  await h.write("go.mod", BASE_GO_MOD.replace("v1.2.3", "v9.9.9"));

  // An unjustified dependency never reaches a human at all (SPEC 11.2).
  const unjustified = await h.call("ls");
  assert.equal(unjustified?.block, true);
  assert.match(unjustified?.reason ?? "", /supplyguard_justify_dependency/);
  assert.deepEqual(h.rec.prompts, [], "nothing to ask about yet");

  // Justified, it becomes a trust decision a human can refuse.
  await h.justify("github.com/foo/bar", "v9.9.9");
  const blocked = await h.call("ls");
  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /Not approved by a human/);
  assert.match(
    h.rec.prompts.join("\n"),
    /DependencyUpgrade github\.com\/foo\/bar@v9\.9\.9/,
    "the human is shown what actually changed",
  );
  assert.match(h.rec.prompts.join("\n"), /Purpose\s+needed for the feature under test/);
});

test("a dependency added by a generated python script is caught the same way", async () => {
  const h = await harness({ answer: "Deny" });
  await h.write("go.mod", BASE_GO_MOD);
  await h.call("python3 rewrite_gomod.py");

  await h.write("go.mod", `${BASE_GO_MOD}\nrequire github.com/evil/pkg v0.0.1\n`);

  const blocked = await h.call("go build ./...");
  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /supplyguard_justify_dependency/);

  await h.justify("github.com/evil/pkg", "v0.0.1");
  assert.equal((await h.call("go build ./..."))?.block, true, "the human still says no");
  assert.match(h.rec.prompts.join("\n"), /DependencyAdd github\.com\/evil\/pkg@v0\.0\.1/);
});

test("a human can approve an out-of-band change once, and it is not re-asked", async () => {
  const h = await harness({ answer: "Approve once" });
  await h.write("go.mod", BASE_GO_MOD);
  await h.call("ls");

  await h.write("go.mod", BASE_GO_MOD.replace("v1.2.3", "v1.3.0"));
  await h.justify("github.com/foo/bar", "v1.3.0");

  assert.equal(await h.call("ls"), undefined, "approved once");
  const promptsAfterApproval = h.rec.prompts.length;

  assert.equal(await h.call("ls"), undefined);
  assert.equal(h.rec.prompts.length, promptsAfterApproval, "the accepted state is the new baseline");
});

// SECURITY: a rejected mutation must not be inherited as the accepted state.
test("a denied mutation keeps being denied until the file is put back", async () => {
  const h = await harness({ answer: "Deny" });
  await h.write("go.mod", BASE_GO_MOD);
  await h.call("ls");

  await h.write("go.mod", BASE_GO_MOD.replace("v1.2.3", "v9.9.9"));
  await h.justify("github.com/foo/bar", "v9.9.9");
  assert.equal((await h.call("ls"))?.block, true);
  assert.equal((await h.call("ls"))?.block, true, "the rejected state is not adopted");

  await h.write("go.mod", BASE_GO_MOD);
  assert.equal(await h.call("ls"), undefined, "reverting the file clears the finding");
});

// The other half of correctness: approved operations must not re-ask for the
// file changes they were approved to make.
test("an approved go get is not re-gated for the go.mod line it wrote", async () => {
  const h = await harness({ answer: "Approve once" });
  await h.write("go.mod", BASE_GO_MOD);

  await h.justify("github.com/foo/bar", "v1.4.0");
  assert.equal(await h.call("go get github.com/foo/bar@v1.4.0"), undefined);
  const promptsAfterGet = h.rec.prompts.length;
  assert.equal(promptsAfterGet, 1, "one approval for the dependency itself");

  // The tool ran and rewrote the manifest.
  await h.write("go.mod", BASE_GO_MOD.replace("v1.2.3", "v1.4.0"));
  await h.write("go.sum", "github.com/foo/bar v1.4.0 h1:abc=\n");

  assert.equal(await h.call("ls"), undefined);
  assert.equal(h.rec.prompts.length, promptsAfterGet, "no second prompt for the same change");
});

// SECURITY: the expectation covers ONE call, not the rest of the session.
test("the expectation from an approved operation does not carry past one call", async () => {
  const h = await harness({ answer: "Approve once" });
  await h.write("go.mod", BASE_GO_MOD);

  await h.justify("github.com/foo/bar", "v1.4.0");
  await h.call("go get github.com/foo/bar@v1.4.0");
  await h.write("go.mod", BASE_GO_MOD.replace("v1.2.3", "v1.4.0"));
  await h.call("ls"); // reconciles the approved change

  await h.write("go.mod", `${BASE_GO_MOD.replace("v1.2.3", "v1.4.0")}\nrequire github.com/evil/pkg v0.0.1\n`);
  await h.justify("github.com/evil/pkg", "v0.0.1");
  const prompts = h.rec.prompts.length;
  await h.call("ls");
  assert.equal(h.rec.prompts.length, prompts + 1, "the later edit is gated on its own");
});

// SECURITY: headless has no human, so an unapproved mutation fails closed.
test("a headless session blocks an out-of-band manifest change", async () => {
  const h = await harness({ hasUI: false });
  await h.write("go.mod", BASE_GO_MOD);
  await h.call("ls");

  await h.write("go.mod", `${BASE_GO_MOD}\nrequire github.com/evil/pkg v0.0.1\n`);
  // Justified but headless: recording a rationale is not approval, and there is
  // no human to give one (SPEC 17.1).
  await h.justify("github.com/evil/pkg", "v0.0.1");
  const blocked = await h.call("ls");
  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /Not approved by a human/);
});

// NEGATIVE: ordinary development must stay free.
test("a repository nobody touches is never gated", async () => {
  const h = await harness({ answer: "Deny" });
  await h.write("go.mod", BASE_GO_MOD);

  for (const command of ["ls", "git status", "gofmt -l .", "cat README.md"]) {
    assert.equal(await h.call(command), undefined, command);
  }
  assert.deepEqual(h.rec.prompts, []);
});

// SECURITY: SupplyGuard reports what it observed, not what it guessed.
test("the state a repository was already in is not reported as a mutation", async () => {
  const h = await harness({ answer: "Deny" });
  await h.write("go.mod", `${BASE_GO_MOD}\nrequire github.com/pre/existing v1.0.0\n`);
  assert.equal(await h.call("ls"), undefined, "the first call establishes the baseline");
  assert.deepEqual(h.rec.prompts, []);
});

// ---------------------------------------------------------------------------
// Vendor model (SPEC 9.2, 9.4)
// ---------------------------------------------------------------------------

test("the vendor question is asked once and remembered across sessions", async () => {
  const h = await harness({ answer: "No — do not enforce vendoring" });
  await h.write("go.mod", BASE_GO_MOD);
  await writeFile(join(h.repo, "vendor-modules-tmp"), "");
  await rm(join(h.repo, "vendor-modules-tmp"));
  await writeFile(join(h.repo, "go.sum"), "");

  // A vendor tree that no longer matches go.mod.
  await import("node:fs/promises").then((fs) => fs.mkdir(join(h.repo, "vendor"), { recursive: true }));
  await h.write("vendor/modules.txt", "# github.com/foo/bar v1.0.0\n## explicit\ngithub.com/foo/bar\n");

  // A supply-chain-relevant call reaches project-state inspection.
  await h.call("go build ./...");

  const vendorPrompts = h.rec.prompts.filter((p) => p.includes("vendor"));
  assert.equal(vendorPrompts.length, 1, "asked exactly once");
  assert.match(vendorPrompts[0] ?? "", /Continue enforcing the repository vendor model\?/);

  const state = JSON.parse(
    await readFile(join(h.home, ".local", "state", "pi-supplyguard", "state.json"), "utf8"),
  ) as { projects: Record<string, { decisions?: Record<string, { value: string }> }> };
  assert.equal(
    state.projects[h.repo]?.decisions?.[VENDOR_MODE_DECISION]?.value,
    "optional",
    "the human's answer is persisted",
  );

  // Asked once: a second relevant call must not prompt again.
  await h.call("go build ./...");
  assert.equal(h.rec.prompts.filter((p) => p.includes("vendor")).length, 1);
});

test("a stale vendor tree warns in standard and blocks in hardened", async () => {
  for (const [profile, expectBlock] of [
    ["standard", false],
    ["hardened", true],
  ] as const) {
    const h = await harness({ answer: "Yes — keep enforcing vendoring", profile });
    await h.write("go.mod", BASE_GO_MOD);
    await import("node:fs/promises").then((fs) =>
      fs.mkdir(join(h.repo, "vendor"), { recursive: true }),
    );
    await h.write(
      "vendor/modules.txt",
      "# github.com/foo/bar v1.0.0\n## explicit\ngithub.com/foo/bar\n",
    );

    const result = await h.call("go build ./...");
    if (expectBlock) {
      assert.equal(result?.block, true, `${profile} must deny completion on vendor drift`);
      assert.match(result?.reason ?? "", /vendor tree no longer matches go\.mod/);
    } else {
      assert.equal(result, undefined, `${profile} warns rather than blocks`);
      assert.ok(
        h.rec.notices.some((n) => n.includes("vendor tree no longer matches")),
        "standard must still say something",
      );
    }
  }
});

// ---------------------------------------------------------------------------
// D14: only an APPROVED manifest-writing operation may vouch for a file change
// ---------------------------------------------------------------------------

// A read-only `go mod` subcommand used to arm the reconciliation expectation,
// because the flag was derived from the subcommand WORD. That gave a free,
// unaudited window to rewrite go.mod with any editing tool.
test("a read-only go subcommand cannot vouch for a manifest rewrite", async () => {
  for (const cover of ["go mod verify", "go mod why all", "go mod graph", "go work sync"]) {
    const h = await harness({ answer: "Deny" });
    await h.write("go.mod", BASE_GO_MOD);
    await h.call("ls");

    assert.equal(await h.call(cover), undefined, `${cover} is not itself gated`);
    await h.write("go.mod", "module example.com/app\n\ngo 1.22\n\nrequire github.com/evil/pkg v6.6.6\n");

    const blocked = await h.call("ls");
    assert.equal(blocked?.block, true, `${cover} must not launder the rewrite`);
  }
});

// SECURITY: "not blocked" is not "approved". A denied mutation must not vouch
// for anything either.
test("a denied manifest-writing command does not vouch for the next change", async () => {
  const h = await harness({ answer: "Deny" });
  await h.write("go.mod", BASE_GO_MOD);
  await h.call("ls");

  assert.equal((await h.call("go mod tidy"))?.block, true, "the human said no");
  await h.write("go.mod", `${BASE_GO_MOD}\nrequire github.com/evil/pkg v0.0.1\n`);

  assert.equal((await h.call("ls"))?.block, true, "the refused command vouches for nothing");
});

// SPEC 17.2: disabling the plugin is not the override mechanism, so the gate
// must never be the only thing standing between the repository and the command
// that fixes it.
test("the command that repairs vendor drift is not denied by that drift", async () => {
  for (const profile of ["hardened", "paranoid"] as const) {
    const h = await harness({ answer: "Approve once", profile });
    await h.write("go.mod", BASE_GO_MOD);
    await import("node:fs/promises").then((fs) =>
      fs.mkdir(join(h.repo, "vendor"), { recursive: true }),
    );
    await h.write(
      "vendor/modules.txt",
      "# github.com/foo/bar v1.0.0\n## explicit\ngithub.com/foo/bar\n",
    );

    assert.equal(
      await h.call("go mod vendor"),
      undefined,
      `${profile} must let the operator refresh the vendor tree`,
    );
    assert.equal(
      (await h.call("go build ./..."))?.block,
      true,
      `${profile} still denies building against a stale tree`,
    );
  }
});
