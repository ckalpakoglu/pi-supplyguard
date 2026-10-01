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
  const parsed = parseConfigLayer({ profile: "hardened", sbom: { format: "cyclonedx" } });
  assert.equal(parsed.layer.profile, "hardened");
  assert.match(parsed.warnings.join(" "), /unsupported configuration key "sbom"/);
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
    socket: "required",
    jevEnabled: false,
    signalsEnabled: false,
  };
  const weakened = tightenConfig(
    base,
    { profile: "standard", releaseAgeMinimumDays: 0, auditEnabled: false, socket: "off", jevEnabled: false },
    "layer",
  );
  assert.deepEqual(weakened.config, base);
  assert.equal(weakened.warnings.length, 4);

  const tightened = tightenConfig(
    base,
    { profile: "paranoid", releaseAgeMinimumDays: 45 },
    "layer",
  );
  assert.equal(tightened.config.profile, "paranoid");
  assert.equal(tightened.config.releaseAgeMinimumDays, 45);
  assert.deepEqual(tightened.warnings, []);
});

// SPEC 8.3 -- `socket.enabled`, and the tighten-only rule applied to it: a
// project may demand Socket, and may not switch off a Socket the workstation
// requires.
test("socket.enabled is parsed in every documented spelling", () => {
  assert.equal(parseConfigLayer({ socket: { enabled: "required" } }).layer.socket, "required");
  assert.equal(parseConfigLayer({ socket: { enabled: true } }).layer.socket, "required");
  assert.equal(parseConfigLayer({ socket: { enabled: false } }).layer.socket, "off");
  assert.equal(parseConfigLayer({ socket: "auto" }).layer.socket, "auto");

  const bad = parseConfigLayer({ socket: { enabled: "sometimes" } });
  assert.equal(bad.layer.socket, undefined);
  assert.match(bad.warnings.join(" "), /invalid "socket.enabled" value/);
});

test("a project may require Socket but may not switch it off", () => {
  const base = { ...COMPILED_SAFE_MINIMUMS, socket: "auto" as const };

  const stricter = tightenConfig(base, { socket: "required" }, "project");
  assert.equal(stricter.config.socket, "required");
  assert.deepEqual(stricter.warnings, []);

  const weaker = tightenConfig(base, { socket: "off" }, "project");
  assert.equal(weaker.config.socket, "auto");
  assert.match(weaker.warnings.join(" "), /weaker than the established baseline/);
});

// M10: the optional analyzer is OFF by default and may only be switched on.
test("jev.enabled is off by default and only tightens", () => {
  assert.equal(COMPILED_SAFE_MINIMUMS.jevEnabled, false);
  assert.equal(parseConfigLayer({ jev: { enabled: true } }).layer.jevEnabled, true);
  assert.equal(parseConfigLayer({ jev: { enabled: "yes" } }).layer.jevEnabled, undefined);
  assert.match(
    parseConfigLayer({ jev: { enabled: "yes" } }).warnings.join(" "),
    /invalid "jev.enabled" value/,
  );

  const on = tightenConfig(COMPILED_SAFE_MINIMUMS, { jevEnabled: true }, "project");
  assert.equal(on.config.jevEnabled, true);
  const offAgain = tightenConfig(on.config, { jevEnabled: false }, "project");
  assert.equal(offAgain.config.jevEnabled, true, "a layer cannot switch it back off");
});
