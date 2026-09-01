import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import {
  COMPILED_SAFE_MINIMUMS,
  loadConfig,
  parseConfigLayer,
  resolvePaths,
  tightenConfig,
  type SupplyGuardConfig,
} from "../../src/core/config.ts";

const tempRoots: string[] = [];

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "supplyguard-config-"));
  tempRoots.push(dir);
  return dir;
}

after(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

interface Fixture {
  readonly repoRoot: string;
  readonly configHome: string;
  readonly stateHome: string;
  readonly env: { XDG_CONFIG_HOME: string; XDG_STATE_HOME: string };
}

async function fixture(): Promise<Fixture> {
  const base = await tempDir();
  const repoRoot = join(base, "repo");
  const configHome = join(base, "config");
  const stateHome = join(base, "state");
  await mkdir(repoRoot, { recursive: true });
  await mkdir(join(configHome, "pi-supplyguard"), { recursive: true });
  return {
    repoRoot,
    configHome,
    stateHome,
    env: { XDG_CONFIG_HOME: configHome, XDG_STATE_HOME: stateHome },
  };
}

async function load(f: Fixture) {
  return loadConfig({ repoRoot: f.repoRoot, env: f.env, home: "/nonexistent-home" });
}

test("SPEC 8.1 paths resolve under XDG when set", () => {
  const paths = resolvePaths(
    "/repo",
    { XDG_CONFIG_HOME: "/xdg/config", XDG_STATE_HOME: "/xdg/state" },
    "/home/user",
  );
  assert.equal(paths.globalConfig, "/xdg/config/pi-supplyguard/config.yaml");
  assert.equal(paths.globalTrust, "/xdg/config/pi-supplyguard/trust.yaml");
  assert.equal(paths.projectConfig, "/repo/.supplyguard.yaml");
  assert.equal(paths.projectTrust, "/repo/.supplyguard-trust.yaml");
  assert.equal(paths.state, "/xdg/state/pi-supplyguard/state.json");
  assert.equal(paths.audit, "/xdg/state/pi-supplyguard/audit.jsonl");
});

test("SPEC 8.1 paths fall back to the documented defaults", () => {
  const paths = resolvePaths("/repo", {}, "/home/user");
  assert.equal(paths.globalConfig, "/home/user/.config/pi-supplyguard/config.yaml");
  assert.equal(paths.state, "/home/user/.local/state/pi-supplyguard/state.json");
  assert.equal(paths.audit, "/home/user/.local/state/pi-supplyguard/audit.jsonl");
});

test("a relative XDG value is ignored, per the XDG specification", () => {
  const paths = resolvePaths("/repo", { XDG_CONFIG_HOME: "relative/path" }, "/home/user");
  assert.equal(paths.globalConfig, "/home/user/.config/pi-supplyguard/config.yaml");
});

test("missing configuration files are not an error: compiled safe minimums apply", async () => {
  const f = await fixture();
  const loaded = await load(f);
  assert.deepEqual(loaded.config, COMPILED_SAFE_MINIMUMS);
  assert.equal(loaded.config.profile, "standard");
  assert.deepEqual(
    loaded.sources.map((s) => [s.kind, s.status]),
    [
      ["compiled", "applied"],
      ["global", "missing"],
      ["project", "missing"],
    ],
  );
  assert.deepEqual(loaded.warnings, []);
});

test("global configuration tightens the compiled minimums", async () => {
  const f = await fixture();
  await writeFile(
    join(f.configHome, "pi-supplyguard", "config.yaml"),
    "version: 1\nprofile: hardened\nreleaseAge:\n  minimumDays: 30\n",
  );
  const loaded = await load(f);
  assert.equal(loaded.config.profile, "hardened");
  assert.equal(loaded.config.releaseAgeMinimumDays, 30);
  assert.deepEqual(loaded.warnings, []);
});

// SECURITY INVARIANT: a project may tighten but never weaken (SPEC 8.2).
test("project configuration tightens the global baseline (positive case)", async () => {
  const f = await fixture();
  await writeFile(
    join(f.configHome, "pi-supplyguard", "config.yaml"),
    "profile: hardened\n",
  );
  await writeFile(join(f.repoRoot, ".supplyguard.yaml"), "profile: paranoid\n");
  const loaded = await load(f);
  assert.equal(loaded.config.profile, "paranoid");
  assert.deepEqual(loaded.warnings, []);
});

test("project configuration cannot weaken the global profile (negative case)", async () => {
  const f = await fixture();
  await writeFile(
    join(f.configHome, "pi-supplyguard", "config.yaml"),
    "profile: paranoid\n",
  );
  await writeFile(join(f.repoRoot, ".supplyguard.yaml"), "profile: standard\n");
  const loaded = await load(f);
  assert.equal(loaded.config.profile, "paranoid");
  assert.equal(loaded.warnings.length, 1);
  assert.match(loaded.warnings[0] ?? "", /project configuration/);
  assert.match(loaded.warnings[0] ?? "", /ignored/);
});

test("project configuration cannot disable auditing or shorten the cooldown", async () => {
  const f = await fixture();
  await writeFile(
    join(f.configHome, "pi-supplyguard", "config.yaml"),
    "releaseAge:\n  minimumDays: 30\n",
  );
  await writeFile(
    join(f.repoRoot, ".supplyguard.yaml"),
    "audit:\n  enabled: false\nreleaseAge:\n  minimumDays: 1\n",
  );
  const loaded = await load(f);
  assert.equal(loaded.config.auditEnabled, true);
  assert.equal(loaded.config.releaseAgeMinimumDays, 30);
  assert.equal(loaded.warnings.length, 2);
});

test("a malformed configuration file falls back to the baseline and warns", async () => {
  const f = await fixture();
  await writeFile(join(f.repoRoot, ".supplyguard.yaml"), "profile: [unclosed\n");
  const loaded = await load(f);
  assert.equal(loaded.config.profile, "standard");
  assert.equal(loaded.sources.at(-1)?.status, "invalid");
  assert.match(loaded.warnings.join(" "), /could not be parsed/);
});

test("an invalid profile value is ignored rather than guessed", async () => {
  const f = await fixture();
  await writeFile(join(f.repoRoot, ".supplyguard.yaml"), "profile: off\n");
  const loaded = await load(f);
  assert.equal(loaded.config.profile, "standard");
  assert.match(loaded.warnings.join(" "), /invalid "profile" value/);
});

test("unsupported keys are reported instead of silently accepted", () => {
  const parsed = parseConfigLayer({ profile: "hardened", socket: { enabled: true } });
  assert.equal(parsed.layer.profile, "hardened");
  assert.match(parsed.warnings.join(" "), /unsupported configuration key "socket"/);
});

test("a non-mapping document is rejected", () => {
  assert.deepEqual(parseConfigLayer(["profile: hardened"]).layer, {});
  assert.deepEqual(parseConfigLayer("profile: hardened").layer, {});
  assert.deepEqual(parseConfigLayer(null).layer, {});
});

test("tightenConfig is monotone for every field", () => {
  const base: SupplyGuardConfig = {
    version: 1,
    profile: "hardened",
    releaseAgeMinimumDays: 20,
    auditEnabled: true,
  };
  const weakened = tightenConfig(
    base,
    { profile: "standard", releaseAgeMinimumDays: 0, auditEnabled: false },
    "layer",
  );
  assert.deepEqual(weakened.config, base);
  assert.equal(weakened.warnings.length, 3);

  const tightened = tightenConfig(
    base,
    { profile: "paranoid", releaseAgeMinimumDays: 45 },
    "layer",
  );
  assert.equal(tightened.config.profile, "paranoid");
  assert.equal(tightened.config.releaseAgeMinimumDays, 45);
  assert.deepEqual(tightened.warnings, []);
});
