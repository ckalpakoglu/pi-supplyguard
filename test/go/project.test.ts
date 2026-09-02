/**
 * Go project detection and the vendor model (SPEC 9, 23.1).
 *
 * Drift is derived from the files rather than from a remembered flag, so these
 * tests are about what `go.mod` and `vendor/modules.txt` say to each other.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { parseGoMod } from "../../src/adapters/go/modfile.ts";
import {
  detectGoProject,
  parseVendorModules,
  vendorDrift,
} from "../../src/adapters/go/project.ts";

const tempRoots: string[] = [];

async function repoWith(files: Readonly<Record<string, string>>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "supplyguard-go-"));
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

const GO_MOD = `module example.com/app

go 1.22

require (
	github.com/foo/bar v1.2.3
	golang.org/x/text v0.14.0 // indirect
)
`;

const MODULES_TXT = `# github.com/foo/bar v1.2.3
## explicit; go 1.21
github.com/foo/bar
# golang.org/x/text v0.14.0
## explicit; go 1.18
golang.org/x/text/language
`;

test("modules.txt parses module, version and explicit marker", () => {
  const modules = parseVendorModules(MODULES_TXT);
  assert.deepEqual(
    modules.map((m) => [m.path, m.version, m.explicit]),
    [
      ["github.com/foo/bar", "v1.2.3", true],
      ["golang.org/x/text", "v0.14.0", true],
    ],
  );
});

test("a module without the explicit marker is not marked explicit", () => {
  const modules = parseVendorModules(
    "# github.com/foo/bar v1.2.3\n## go 1.21\ngithub.com/foo/bar\n",
  );
  assert.equal(modules[0]?.explicit, false);
});

test("package lines and replace arrows do not become modules", () => {
  const modules = parseVendorModules(
    "# github.com/foo/bar v1.2.3 => github.com/fork/bar v1.9.9\n## explicit\ngithub.com/foo/bar\n",
  );
  assert.deepEqual(
    modules.map((m) => [m.path, m.version]),
    [["github.com/foo/bar", "v1.2.3"]],
  );
});

test("a matching vendor tree is not drift", () => {
  assert.deepEqual(vendorDrift(parseGoMod(GO_MOD), parseVendorModules(MODULES_TXT)), []);
});

test("a version mismatch between go.mod and the vendor tree is drift", () => {
  const bumped = GO_MOD.replace("v1.2.3", "v1.3.0");
  const reasons = vendorDrift(parseGoMod(bumped), parseVendorModules(MODULES_TXT));
  assert.equal(reasons.length, 1);
  assert.match(reasons[0] ?? "", /github\.com\/foo\/bar v1\.2\.3.*requires v1\.3\.0/);
});

test("a vendored explicit module go.mod no longer requires is drift", () => {
  const dropped = GO_MOD.replace("\tgithub.com/foo/bar v1.2.3\n", "");
  const reasons = vendorDrift(parseGoMod(dropped), parseVendorModules(MODULES_TXT));
  assert.equal(reasons.length, 1);
  assert.match(reasons[0] ?? "", /marks github\.com\/foo\/bar explicit/);
});

// NEGATIVE: `go mod vendor` only vendors imported packages, so a required but
// unimported module legitimately has no vendor entry.
test("a requirement missing from the vendor tree is not drift", () => {
  const extra = GO_MOD.replace(
    "require (",
    "require (\n\tgithub.com/unused/dep v0.1.0",
  );
  assert.deepEqual(vendorDrift(parseGoMod(extra), parseVendorModules(MODULES_TXT)), []);
});

// NEGATIVE: a replaced module's vendored version describes the replacement.
test("a replaced module is not compared against the requirement it redirects", () => {
  const replaced = `${GO_MOD}\nreplace github.com/foo/bar => github.com/fork/bar v9.9.9\n`;
  const vendored = parseVendorModules(
    "# github.com/foo/bar v1.2.3 => github.com/fork/bar v9.9.9\n## explicit\n",
  );
  assert.deepEqual(vendorDrift(parseGoMod(replaced), vendored), []);
});

test("a repository with no Go signals is not a Go project", async () => {
  const repo = await repoWith({ "README.md": "hello\n" });
  const project = await detectGoProject(repo);
  assert.equal(project.isGoProject, false);
  assert.equal(project.vendorState, "absent");
});

test("go.mod without a vendor tree detects as absent vendoring", async () => {
  const repo = await repoWith({ "go.mod": GO_MOD, "go.sum": "" });
  const project = await detectGoProject(repo);
  assert.deepEqual(
    [project.isGoProject, project.hasGoMod, project.hasGoSum, project.hasVendorTree],
    [true, true, true, false],
  );
  assert.equal(project.vendorState, "absent");
});

test("a consistent vendor tree detects as current", async () => {
  const repo = await repoWith({ "go.mod": GO_MOD, "vendor/modules.txt": MODULES_TXT });
  const project = await detectGoProject(repo);
  assert.equal(project.hasVendorTree, true);
  assert.equal(project.vendorState, "current");
  assert.deepEqual(project.driftReasons, []);
});

test("a stale vendor tree detects as stale and explains why", async () => {
  const repo = await repoWith({
    "go.mod": GO_MOD.replace("v1.2.3", "v1.3.0"),
    "vendor/modules.txt": MODULES_TXT,
  });
  const project = await detectGoProject(repo);
  assert.equal(project.vendorState, "stale");
  assert.equal(project.driftReasons.length, 1);
});

test("a go.work-only repository is still a Go project", async () => {
  const repo = await repoWith({ "go.work": "go 1.22\n\nuse ./app\n" });
  const project = await detectGoProject(repo);
  assert.equal(project.isGoProject, true);
  assert.equal(project.hasGoWork, true);
  assert.equal(project.hasGoMod, false);
});
