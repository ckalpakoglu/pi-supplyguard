import assert from "node:assert/strict";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import {
  EMPTY_STATE,
  getProjectState,
  loadState,
  parseState,
  saveState,
  setProjectState,
} from "../../src/core/state.ts";

const tempRoots: string[] = [];

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "supplyguard-state-"));
  tempRoots.push(dir);
  return dir;
}

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

test("a missing state file is not an error", async () => {
  const dir = await tempDir();
  assert.deepEqual(await loadState(join(dir, "missing", "state.json")), EMPTY_STATE);
});

test("a corrupt state file degrades to nothing remembered", async () => {
  const dir = await tempDir();
  const path = join(dir, "state.json");
  await writeFile(path, "{not json");
  assert.deepEqual(await loadState(path), EMPTY_STATE);

  await writeFile(path, JSON.stringify({ projects: "nope" }));
  assert.deepEqual(await loadState(path), EMPTY_STATE);
});

test("state round-trips with restrictive permissions", async () => {
  const dir = await tempDir();
  const path = join(dir, "nested", "state.json");
  const state = setProjectState(EMPTY_STATE, "/repo", {
    lastEffectiveProfile: "paranoid",
    lastSeenAt: "2026-09-01T00:00:00.000Z",
  });

  await saveState(path, state);
  const loaded = await loadState(path);
  assert.deepEqual(getProjectState(loaded, "/repo"), {
    lastEffectiveProfile: "paranoid",
    lastSeenAt: "2026-09-01T00:00:00.000Z",
  });

  const mode = (await stat(path)).mode & 0o777;
  assert.equal(mode & 0o077, 0, "state must not be group/other readable");
});

test("setProjectState is pure and merges", () => {
  const first = setProjectState(EMPTY_STATE, "/repo", { lastEffectiveProfile: "hardened" });
  assert.deepEqual(EMPTY_STATE.projects, {});

  const second = setProjectState(first, "/repo", { lastSeenAt: "later" });
  assert.deepEqual(getProjectState(second, "/repo"), {
    lastEffectiveProfile: "hardened",
    lastSeenAt: "later",
  });
  assert.equal(getProjectState(first, "/repo")?.lastSeenAt, undefined);
});

test("untrusted state values are not resurrected as trust", () => {
  const parsed = parseState({
    version: 1,
    projects: {
      "/repo": { lastEffectiveProfile: "godmode", extra: { firewall: "enabled" } },
    },
  });
  assert.deepEqual(getProjectState(parsed, "/repo"), {});
});

test("unknown project state is undefined", () => {
  assert.equal(getProjectState(EMPTY_STATE, "/nope"), undefined);
});
