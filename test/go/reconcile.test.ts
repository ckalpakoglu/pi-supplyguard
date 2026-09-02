/**
 * Indirect manifest mutation (SPEC 14, 23.2).
 *
 * The command gate cannot see `sed -i go.mod`, `python rewrite.py` or a
 * generated script. These tests exercise the other half of the model: an
 * observed before/after change to a tracked file becomes the SAME normalized
 * event a `go get` would have produced, so it reaches the same trust decision.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { createGoAdapter, VENDOR_MODE_DECISION, VENDOR_OPTIONAL } from "../../src/adapters/go/index.ts";
import type { SupplyChainEvent } from "../../src/core/events.ts";
import type { FileMutation } from "../../src/core/manifest.ts";

const adapter = createGoAdapter();

const BASE = `module example.com/app

go 1.22

require github.com/foo/bar v1.2.3
`;

function mutation(before: string | undefined, after: string | undefined, path = "go.mod"): FileMutation {
  return {
    path,
    ...(before === undefined ? {} : { before }),
    ...(after === undefined ? {} : { after }),
    existedBefore: before !== undefined,
    existsAfter: after !== undefined,
    contentAvailable: true,
  };
}

function inspect(m: FileMutation): readonly SupplyChainEvent[] {
  const events = adapter.inspectFileMutation?.(m, { repoRoot: "/repo", profile: "standard" });
  assert.ok(events !== undefined, "the Go adapter must classify file mutations");
  return events as readonly SupplyChainEvent[];
}

function classes(events: readonly SupplyChainEvent[]): string[] {
  return events.map((e) => e.eventClass);
}

test("the Go adapter tracks exactly the SPEC 14.1 Go files", () => {
  assert.deepEqual(adapter.sensitivePaths?.(), [
    "go.mod",
    "go.sum",
    "go.work",
    "go.work.sum",
    "vendor/modules.txt",
  ]);
});

// The core bypass: an editing tool adds a dependency the gate never saw.
test("a dependency added by an editing tool becomes a DependencyAdd", () => {
  const after = `${BASE}\nrequire github.com/evil/pkg v0.0.1\n`;
  const events = inspect(mutation(BASE, after));

  assert.deepEqual(classes(events), ["DependencyAdd"]);
  assert.equal(events[0]?.artifact, "github.com/evil/pkg");
  assert.equal(events[0]?.version, "v0.0.1");
  assert.equal(
    events[0]?.classification,
    "THIRD_PARTY_MUTATION",
    "an observed dependency change is a mutation whatever tool made it",
  );
});

test("sed-style version rewrites are classified as upgrade or downgrade", () => {
  assert.deepEqual(
    classes(inspect(mutation(BASE, BASE.replace("v1.2.3", "v1.9.0")))),
    ["DependencyUpgrade"],
  );
  assert.deepEqual(
    classes(inspect(mutation(BASE, BASE.replace("v1.2.3", "v1.0.0")))),
    ["DependencyDowngrade"],
  );
});

test("a remote replace is distinguished from a local one", () => {
  const remote = inspect(mutation(BASE, `${BASE}\nreplace github.com/foo/bar => github.com/evil/bar v1.2.3\n`));
  assert.deepEqual(classes(remote), ["DependencyReplace"]);
  assert.equal(remote[0]?.detail?.["remote"], true);
  assert.match(remote[0]?.summary ?? "", /REMOTE/);

  const local = inspect(mutation(BASE, `${BASE}\nreplace github.com/foo/bar => ../bar\n`));
  assert.equal(local[0]?.detail?.["remote"], false);
});

// NEGATIVE: reformatting is not a dependency change.
test("reformatting go.mod produces no events", () => {
  const block = "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/foo/bar v1.2.3\n)\n";
  assert.deepEqual(inspect(mutation(BASE, block)), []);
});

// NEGATIVE: a comment edit is not a dependency change.
test("adding a comment to go.mod produces no events", () => {
  assert.deepEqual(inspect(mutation(BASE, `// generated\n${BASE}`)), []);
});

test("deleting go.sum is a checksum bypass, denied in every profile", () => {
  const events = inspect(mutation("github.com/foo/bar v1.2.3 h1:abc=\n", undefined, "go.sum"));
  assert.deepEqual(classes(events), ["ChecksumBypass"]);
  assert.equal(events[0]?.minimumDecision, "deny");
});

test("editing go.sum is a lockfile mutation that reports what changed", () => {
  const events = inspect(
    mutation(
      "github.com/foo/bar v1.2.3 h1:abc=\n",
      "github.com/foo/bar v1.2.3 h1:TAMPERED=\n",
      "go.sum",
    ),
  );
  assert.deepEqual(classes(events), ["LockfileMutation"]);
  assert.equal(events[0]?.detail?.["added"], 1);
  assert.equal(events[0]?.detail?.["removed"], 1);
});

test("go.work and vendor/modules.txt edits are lockfile mutations", () => {
  assert.deepEqual(classes(inspect(mutation("go 1.22\n", "go 1.23\n", "go.work"))), [
    "LockfileMutation",
  ]);
  assert.deepEqual(
    classes(inspect(mutation("# a v1.0.0\n", "# a v2.0.0\n", "vendor/modules.txt"))),
    ["LockfileMutation"],
  );
});

// SECURITY: unclassifiable must never read as harmless.
test("a change too large to classify is still an unreviewed mutation", () => {
  const events = inspect({
    path: "go.sum",
    existedBefore: true,
    existsAfter: true,
    contentAvailable: false,
  });
  assert.deepEqual(classes(events), ["LockfileMutation"]);
  assert.match(events[0]?.summary ?? "", /too large to classify/);
});

test("deleting go.mod is reported rather than read as an empty manifest", () => {
  const events = inspect(mutation(BASE, undefined));
  assert.deepEqual(classes(events), ["LockfileMutation"]);
  assert.match(events[0]?.summary ?? "", /deleted/);
});

// ---------------------------------------------------------------------------
// Vendor model (SPEC 9.2, 9.3)
// ---------------------------------------------------------------------------

test("the vendor question is asked once, and never in paranoid", async () => {
  const withVendor = { repoRoot: process.cwd(), profile: "standard" as const, decisions: {} };

  // This repository has no vendor tree, so there is nothing to keep enforcing.
  assert.deepEqual(await adapter.projectDecisions?.(withVendor), []);

  assert.deepEqual(
    await adapter.projectDecisions?.({ ...withVendor, profile: "paranoid" }),
    [],
    "paranoid enforces vendoring and has no weakening choice to offer",
  );

  assert.deepEqual(
    await adapter.projectDecisions?.({
      ...withVendor,
      decisions: { [VENDOR_MODE_DECISION]: VENDOR_OPTIONAL },
    }),
    [],
    "an answered question is not asked again",
  );
});

// ---------------------------------------------------------------------------
// Vendor state as an enforcement signal
// ---------------------------------------------------------------------------

const tempRoots: string[] = [];

async function repoWith(files: Readonly<Record<string, string>>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "supplyguard-vendor-"));
  tempRoots.push(dir);
  for (const [path, content] of Object.entries(files)) {
    const full = join(dir, path);
    await mkdir(join(full, ".."), { recursive: true });
    await writeFile(full, content);
  }
  return dir;
}

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

const VENDORED = {
  "go.mod": BASE,
  "vendor/modules.txt": "# github.com/foo/bar v1.2.3\n## explicit; go 1.21\ngithub.com/foo/bar\n",
};

async function projectState(
  repoRoot: string,
  profile: "standard" | "hardened" | "paranoid",
  options: {
    readonly classification?: "SUPPLY_CHAIN_IRRELEVANT" | "THIRD_PARTY_CAPABLE" | "THIRD_PARTY_MUTATION";
    readonly decisions?: Readonly<Record<string, string>>;
  } = {},
) {
  const result = await adapter.inspectProjectState?.({
    repoRoot,
    profile,
    decisions: options.decisions ?? {},
    classification: options.classification ?? "THIRD_PARTY_CAPABLE",
  });
  assert.ok(result !== undefined, "the Go adapter must report project state");
  return result;
}

test("an existing vendor tree is asked about once, per SPEC 9.2", async () => {
  const repo = await repoWith(VENDORED);
  const requests = await adapter.projectDecisions?.({
    repoRoot: repo,
    profile: "standard",
    decisions: {},
  });
  assert.equal(requests?.length, 1);
  assert.equal(requests?.[0]?.id, VENDOR_MODE_DECISION);
  assert.equal(requests?.[0]?.recommended, "enforce", "SPEC 9.2: the default is Yes");
  assert.equal(
    requests?.[0]?.headlessValue,
    "enforce",
    "no human present must not weaken the repository's own model",
  );
});

test("a consistent vendor tree produces no events", async () => {
  const repo = await repoWith(VENDORED);
  assert.deepEqual((await projectState(repo, "hardened")).events, []);
});

test("a stale vendor tree is VendorDrift while vendoring is enforced", async () => {
  const repo = await repoWith({ ...VENDORED, "go.mod": BASE.replace("v1.2.3", "v1.4.0") });
  const events = (await projectState(repo, "standard")).events;
  assert.deepEqual(classes(events), ["VendorDrift"]);
  assert.match(events[0]?.summary ?? "", /go mod vendor/);
});

// The human answered "No"; SPEC 9.2 allows that, and it must actually apply.
test("declining the vendor model stops drift from being reported", async () => {
  const repo = await repoWith({ ...VENDORED, "go.mod": BASE.replace("v1.2.3", "v1.4.0") });
  const events = (
    await projectState(repo, "standard", {
      decisions: { [VENDOR_MODE_DECISION]: VENDOR_OPTIONAL },
    })
  ).events;
  assert.deepEqual(events, []);
});

// SECURITY: paranoid has no weakening choice (SPEC 4.3).
test("paranoid reports drift even when the vendor model was declined", async () => {
  const repo = await repoWith({ ...VENDORED, "go.mod": BASE.replace("v1.2.3", "v1.4.0") });
  const events = (
    await projectState(repo, "paranoid", {
      decisions: { [VENDOR_MODE_DECISION]: VENDOR_OPTIONAL },
    })
  ).events;
  assert.deepEqual(classes(events), ["VendorDrift"]);
});

test("paranoid denies a dependency mutation in a project with no vendor tree", async () => {
  const repo = await repoWith({ "go.mod": BASE });
  const events = (
    await projectState(repo, "paranoid", { classification: "THIRD_PARTY_MUTATION" })
  ).events;
  assert.deepEqual(classes(events), ["VendorDrift"]);
  assert.equal(events[0]?.minimumDecision, "deny");
});

// NEGATIVE: paranoid gates dependency mutation, not working in the repository.
test("paranoid does not deny a build merely because the project is not vendored", async () => {
  const repo = await repoWith({ "go.mod": BASE });
  const events = (
    await projectState(repo, "paranoid", { classification: "THIRD_PARTY_CAPABLE" })
  ).events;
  assert.deepEqual(events, []);
});

test("hardened records a vendoring recommendation as evidence, not as a gate", async () => {
  const repo = await repoWith({ "go.mod": BASE });
  const state = await projectState(repo, "hardened", { classification: "THIRD_PARTY_MUTATION" });
  assert.deepEqual(state.events, []);
  assert.equal(state.notes?.length, 1);
  assert.match(state.notes?.[0] ?? "", /not vendored/);
});

test("a repository with no Go project reports nothing", async () => {
  const repo = await repoWith({ "README.md": "hi\n" });
  assert.deepEqual((await projectState(repo, "paranoid")).events, []);
});

test("status lines describe the vendor state without leaking paths", async () => {
  const repo = await repoWith(VENDORED);
  const lines = await adapter.describe?.({ repoRoot: repo, profile: "standard", decisions: {} });
  assert.ok(lines?.some((line) => line.includes("vendor current")), lines?.join("\n"));
});
