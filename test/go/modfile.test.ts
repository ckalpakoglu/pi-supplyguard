/**
 * `go.mod` / `go.sum` parsing and semantic classification (SPEC 10.5, 23.1).
 *
 * Corpus-driven: every change kind gets positive cases (block/inline forms,
 * /v2 modules, pseudo-versions, indirect flags, remote vs local replaces) and
 * negative cases (reformatting, comments and untouched directives are not
 * dependency changes).
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  compareVersions,
  diffGoMod,
  diffGoSum,
  isLocalReplaceTarget,
  parseGoMod,
  parseGoSum,
  type GoModChange,
} from "../../src/adapters/go/modfile.ts";

function kinds(changes: readonly GoModChange[]): string[] {
  return changes.map((c) => c.kind);
}

function diffText(before: string, after: string) {
  return diffGoMod(parseGoMod(before), parseGoMod(after));
}

const BASE = `module example.com/app

go 1.22

require github.com/foo/bar v1.2.3

require (
	github.com/baz/qux v2.1.0+incompatible // indirect
	golang.org/x/text v0.14.0
)
`;

test("parseGoMod reads module, go and toolchain", () => {
  const mod = parseGoMod(
    `module example.com/app

go 1.22

toolchain go1.22.3
`,
  );
  assert.equal(mod.module, "example.com/app");
  assert.equal(mod.go, "1.22");
  assert.equal(mod.toolchain, "go1.22.3");
});

test("parseGoMod reads inline and block requires with indirect markers", () => {
  const mod = parseGoMod(BASE);
  assert.deepEqual(
    mod.requires.map((r) => [r.path, r.version, r.indirect]),
    [
      ["github.com/foo/bar", "v1.2.3", false],
      ["github.com/baz/qux", "v2.1.0+incompatible", true],
      ["golang.org/x/text", "v0.14.0", false],
    ],
  );
});

test("parseGoMod reads replace directives, local and remote", () => {
  const mod = parseGoMod(
    `module example.com/app

replace github.com/foo/bar => ../bar

replace (
	github.com/baz/qux => github.com/other/qux v1.9.0
	golang.org/x/text v0.14.0 => golang.org/x/text v0.15.0
)
`,
  );
  assert.deepEqual(
    mod.replaces.map((r) => [r.from, r.to, r.version ?? "-"]),
    [
      ["github.com/foo/bar", "../bar", "-"],
      ["github.com/baz/qux", "github.com/other/qux", "v1.9.0"],
      ["golang.org/x/text", "golang.org/x/text", "v0.15.0"],
    ],
  );
});

test("parseGoMod reads exclude and retract", () => {
  const mod = parseGoMod(
    `module example.com/app

exclude github.com/bad/pkg v1.0.1

retract v1.0.2

retract [v1.0.0, v1.0.1]
`,
  );
  assert.equal(mod.excludes.length, 1);
  assert.deepEqual(mod.excludes[0], { path: "github.com/bad/pkg", version: "v1.0.1" });
  assert.equal(mod.retracts.length, 2);
});

test("parseGoMod ignores comments and blank lines, keeps unknown directives visible", () => {
  const mod = parseGoMod(`module example.com/app

// a comment
godebug x=1
`);
  assert.equal(mod.module, "example.com/app");
  assert.deepEqual(mod.unparsed, ["godebug x=1"]);
});

test("an identical document diffs to nothing", () => {
  const diff = diffText(BASE, BASE);
  assert.equal(diff.changes.length, 0);
  assert.equal(diff.dependencyGraphChanged, false);
  assert.equal(diff.metadataChanged, false);
});

test("reformatting between inline and block require is not a change", () => {
  const inline = "module example.com/app\n\ngo 1.22\n\nrequire github.com/foo/bar v1.2.3\n";
  const block =
    "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/foo/bar v1.2.3\n)\n";
  const diff = diffText(inline, block);
  assert.equal(diff.changes.length, 0);
});

test("adding a require is classified as add", () => {
  const after = BASE.replace(
    "require github.com/foo/bar v1.2.3",
    "require github.com/foo/bar v1.2.3\n\nrequire github.com/new/dep v0.1.0",
  );
  const diff = diffText(BASE, after);
  assert.deepEqual(kinds(diff.changes), ["add"]);
  assert.equal(diff.changes[0]?.kind === "add" ? diff.changes[0].require.path : "", "github.com/new/dep");
  assert.equal(diff.dependencyGraphChanged, true);
});

test("version bump is classified as upgrade", () => {
  const diff = diffText(BASE, BASE.replace("github.com/foo/bar v1.2.3", "github.com/foo/bar v1.3.0"));
  assert.deepEqual(kinds(diff.changes), ["upgrade"]);
  if (diff.changes[0]?.kind === "upgrade") {
    assert.equal(diff.changes[0].from, "v1.2.3");
    assert.equal(diff.changes[0].require.version, "v1.3.0");
  }
});

test("version drop is classified as downgrade", () => {
  const diff = diffText(BASE, BASE.replace("github.com/foo/bar v1.2.3", "github.com/foo/bar v1.1.9"));
  assert.deepEqual(kinds(diff.changes), ["downgrade"]);
});

test("removing a require is classified as remove", () => {
  const diff = diffText(
    BASE,
    BASE.replace("\tgolang.org/x/text v0.14.0\n", "").replace("\n", "\n"),
  );
  assert.ok(kinds(diff.changes).includes("remove"));
});

test("a /v2 module is a distinct artifact, not an upgrade of v1", () => {
  const mod = parseGoMod("module example.com/app\n\ngo 1.22\n\nrequire github.com/foo/bar/v2 v2.0.0\n");
  const before = parseGoMod("module example.com/app\n\ngo 1.22\n\nrequire github.com/foo/bar v1.9.0\n");
  const diff = diffGoMod(before, mod);
  assert.deepEqual(kinds(diff.changes), ["add", "remove"]);
});

test("pseudo-version upgrade by timestamp is classified as upgrade", () => {
  const old = "v0.0.0-20230101120000-abcdef123456";
  const neu = "v0.0.0-20230602030000-123456abcdef";
  const diff = diffText(BASE.replace("v1.2.3", old), BASE.replace("v1.2.3", neu));
  assert.deepEqual(kinds(diff.changes), ["upgrade"]);
});

test("pseudo-version downgrade by timestamp is classified as downgrade", () => {
  const old = "v0.0.0-20230101120000-abcdef123456";
  const neu = "v0.0.0-20220101000000-123456abcdef";
  const diff = diffText(BASE.replace("v1.2.3", old), BASE.replace("v1.2.3", neu));
  assert.deepEqual(kinds(diff.changes), ["downgrade"]);
});

test("indirect flag change is its own kind", () => {
  const diff = diffText(BASE, BASE.replace("// indirect", ""));
  assert.deepEqual(kinds(diff.changes), ["indirect-flag"]);
  assert.equal(diff.dependencyGraphChanged, true);
});

test("replace add, change and remove are classified", () => {
  const withReplace = `${BASE}\nreplace github.com/foo/bar => ../bar\n`;
  const added = diffText(BASE, withReplace);
  assert.deepEqual(kinds(added.changes), ["replace-add"]);

  const changed = diffText(
    withReplace,
    `${BASE}\nreplace github.com/foo/bar => ../other/bar\n`,
  );
  assert.deepEqual(kinds(changed.changes), ["replace-change"]);

  const removed = diffText(withReplace, BASE);
  assert.deepEqual(kinds(removed.changes), ["replace-remove"]);
});

test("remote replaces are distinguishable from local ones", () => {
  assert.equal(isLocalReplaceTarget("../bar"), true);
  assert.equal(isLocalReplaceTarget("./local"), true);
  assert.equal(isLocalReplaceTarget("/abs/path"), true);
  assert.equal(isLocalReplaceTarget("."), true);
  assert.equal(isLocalReplaceTarget("github.com/other/qux"), false);
  const mod = parseGoMod("module m\n\nreplace github.com/foo/bar => github.com/evil/bar v9.9.9\n");
  assert.equal(mod.replaces[0]?.version, "v9.9.9");
  assert.equal(isLocalReplaceTarget(mod.replaces[0]?.to ?? ""), false);
});

test("exclude add and remove are classified", () => {
  const withExclude = `${BASE}\nexclude github.com/bad/pkg v1.0.1\n`;
  assert.deepEqual(kinds(diffText(BASE, withExclude).changes), ["exclude-add"]);
  assert.deepEqual(kinds(diffText(withExclude, BASE).changes), ["exclude-remove"]);
});

test("module, go and toolchain changes are metadata, not graph changes", () => {
  const diff = diffText(BASE, BASE.replace("go 1.22", "go 1.23"));
  assert.deepEqual(kinds(diff.changes), ["other"]);
  assert.equal(diff.dependencyGraphChanged, false);
  assert.equal(diff.metadataChanged, true);
});

test("a retracted version range is preserved as one entry", () => {
  const withRetract = `${BASE}\nretract [v1.0.0, v1.0.2]\n`;
  const diff = diffText(BASE, withRetract);
  assert.ok(kinds(diff.changes).includes("other"));
});

test("version comparison ordering", () => {
  assert.equal(compareVersions("v1.2.3", "v1.2.3"), 0);
  assert.equal(compareVersions("v1.2.3", "v1.10.0") < 0, true);
  assert.equal(compareVersions("v2.0.0", "v1.99.99") > 0, true);
  assert.equal(compareVersions("v1.2.3-pre", "v1.2.3") < 0, true);
  assert.equal(compareVersions("v1.2.3-rc.2", "v1.2.3-rc.10") < 0, true);
  const early = "v0.0.0-20200101000000-aaaaaaaaaaaa";
  const late = "v0.0.0-20240101000000-bbbbbbbbbbbb";
  assert.equal(compareVersions(early, late) < 0, true);
  // Canonical pseudo with base sorts before its own release.
  assert.equal(compareVersions("v1.2.3-0.20230101120000-abcdef123456", "v1.2.3") < 0, true);
});

test("unparseable versions are never silently equal", () => {
  assert.equal(compareVersions("v1.2.3", "not-a-version") !== 0, true);
  assert.equal(compareVersions("garbage-a", "garbage-a"), 0);
});

test("go.sum entries parse with and without the /go.mod suffix", () => {
  const entries = parseGoSum(
    "github.com/foo/bar v1.2.3 h1:abc=\ngithub.com/foo/bar v1.2.3/go.mod h1:def=\n",
  );
  assert.equal(entries.length, 2);
  assert.equal(entries[0]?.goModHash, false);
  assert.equal(entries[1]?.goModHash, true);
  assert.equal(entries[1]?.version, "v1.2.3");
});

test("go.sum diff reports added and removed lines", () => {
  const before = parseGoSum("github.com/foo/bar v1.2.3 h1:abc=\ngithub.com/foo/bar v1.2.3/go.mod h1:def=\n");
  const after = parseGoSum("github.com/foo/bar v1.2.3 h1:abc=\ngithub.com/foo/bar v1.3.0 h1:xyz=\ngithub.com/foo/bar v1.3.0/go.mod h1:uvw=\n");
  const diff = diffGoSum(before, after);
  assert.equal(diff.added.length, 2);
  assert.equal(diff.removed.length, 1);
  assert.equal(diff.removed[0]?.version, "v1.2.3");
});
