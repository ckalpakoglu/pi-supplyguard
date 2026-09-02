/**
 * Manifest integrity snapshots (SPEC 14.1, 23.1).
 *
 * The snapshot is the only reason SupplyGuard can see a `sed -i go.mod`, so
 * its failure modes matter: a missed change is a silent bypass, and a change
 * reported as "unchanged" because the file was unreadable would be worse.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import {
  describeMutation,
  diffManifestSnapshot,
  MAX_TRACKED_BYTES,
  readManifestSnapshot,
} from "../../src/core/manifest.ts";

const tempRoots: string[] = [];

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "supplyguard-manifest-"));
  tempRoots.push(dir);
  return dir;
}

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

const WATCHED = ["go.mod", "go.sum", "vendor/modules.txt"];

test("an absent file is recorded as absent, not omitted", async () => {
  const repo = await tempDir();
  const snapshot = await readManifestSnapshot(repo, WATCHED);

  assert.deepEqual(Object.keys(snapshot).sort(), [...WATCHED].sort());
  for (const path of WATCHED) assert.equal(snapshot[path], null);
});

test("content and hash are captured for a tracked file", async () => {
  const repo = await tempDir();
  await writeFile(join(repo, "go.mod"), "module example.com/app\n");

  const snapshot = await readManifestSnapshot(repo, WATCHED);
  const file = snapshot["go.mod"];
  assert.notEqual(file, null);
  assert.equal(file?.text, "module example.com/app\n");
  assert.match(file?.hash ?? "", /^[0-9a-f]{64}$/);
  assert.equal(file?.bytes, "module example.com/app\n".length);
});

test("an identical repository diffs to nothing", async () => {
  const repo = await tempDir();
  await writeFile(join(repo, "go.mod"), "module example.com/app\n");

  const before = await readManifestSnapshot(repo, WATCHED);
  const after = await readManifestSnapshot(repo, WATCHED);
  assert.deepEqual(diffManifestSnapshot(before, after), []);
});

test("creation, modification and deletion are each reported", async () => {
  const repo = await tempDir();
  const goMod = join(repo, "go.mod");
  const goSum = join(repo, "go.sum");
  await writeFile(goSum, "github.com/foo/bar v1.0.0 h1:abc=\n");

  const before = await readManifestSnapshot(repo, WATCHED);

  await writeFile(goMod, "module example.com/app\n");
  await rm(goSum);
  const after = await readManifestSnapshot(repo, WATCHED);

  const changes = diffManifestSnapshot(before, after);
  assert.deepEqual(
    changes.map((c) => [c.path, c.existedBefore, c.existsAfter]),
    [
      ["go.mod", false, true],
      ["go.sum", true, false],
    ],
  );
  assert.equal(describeMutation(changes[0] as never), "go.mod was created");
  assert.equal(describeMutation(changes[1] as never), "go.sum was deleted");
});

test("a nested tracked path is snapshotted", async () => {
  const repo = await tempDir();
  await mkdir(join(repo, "vendor"), { recursive: true });
  await writeFile(join(repo, "vendor", "modules.txt"), "# github.com/foo/bar v1.0.0\n");

  const snapshot = await readManifestSnapshot(repo, WATCHED);
  assert.equal(snapshot["vendor/modules.txt"]?.text, "# github.com/foo/bar v1.0.0\n");
});

// SECURITY: a declared path must not be able to read outside the repository.
test("a path escaping the repository is refused, not followed", async () => {
  const repo = await tempDir();
  await writeFile(join(repo, "secret.txt"), "not yours\n");
  const nested = join(repo, "sub");
  await mkdir(nested, { recursive: true });

  const snapshot = await readManifestSnapshot(nested, [
    "../secret.txt",
    join(repo, "secret.txt"),
    "go.mod",
  ]);
  assert.deepEqual(Object.keys(snapshot), ["go.mod"]);
});

// SECURITY: unreadable must never read as unchanged.
test("a file replaced by a directory is reported as absent, then as a change", async () => {
  const repo = await tempDir();
  await writeFile(join(repo, "go.mod"), "module example.com/app\n");
  const before = await readManifestSnapshot(repo, ["go.mod"]);

  await rm(join(repo, "go.mod"));
  await mkdir(join(repo, "go.mod"));
  const after = await readManifestSnapshot(repo, ["go.mod"]);

  const changes = diffManifestSnapshot(before, after);
  assert.equal(changes.length, 1);
  assert.equal(changes[0]?.existsAfter, false);
});

test("a file too large to retain still reports a change, without content", async () => {
  const repo = await tempDir();
  const goSum = join(repo, "go.sum");
  await writeFile(goSum, "x".repeat(MAX_TRACKED_BYTES + 1));
  const before = await readManifestSnapshot(repo, ["go.sum"]);
  assert.equal(before["go.sum"]?.text, undefined);

  await writeFile(goSum, "y".repeat(MAX_TRACKED_BYTES + 1));
  const after = await readManifestSnapshot(repo, ["go.sum"]);

  const changes = diffManifestSnapshot(before, after);
  assert.equal(changes.length, 1, "an unclassifiable change is still a change");
  assert.equal(changes[0]?.contentAvailable, false);
});

test("a watched path added mid-session is compared against absent", () => {
  const changes = diffManifestSnapshot(
    {},
    { "go.mod": { hash: "abc", bytes: 3, text: "mod" } },
  );
  assert.deepEqual(
    changes.map((c) => [c.path, c.existedBefore, c.existsAfter]),
    [["go.mod", false, true]],
  );
});
