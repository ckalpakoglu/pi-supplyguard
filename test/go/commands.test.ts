/**
 * Go command recognition and the exact-version / checksum rules
 * (SPEC 10.2, 10.3, 23.1).
 *
 * Every security-sensitive rule gets both directions: a positive case where
 * the risky operation is caught, and a negative case where legitimate work
 * stays out of the way.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { analyzeCommand, isExactVersion } from "../../src/adapters/go/commands.ts";
import type { GoAnalysis } from "../../src/adapters/go/commands.ts";

function denied(analysis: GoAnalysis): boolean {
  return analysis.operations.some((op) => op.minimumDecision === "deny");
}

function classes(analysis: GoAnalysis): string[] {
  return analysis.operations.map((op) => op.eventClass);
}

// ---------------------------------------------------------------------------
// Exact versions (SPEC 10.2)
// ---------------------------------------------------------------------------

test("exact versions are semantic versions or full commit hashes", () => {
  for (const good of [
    "v1.7.2",
    "v0.0.0-20230101120000-abcdef123456",
    "v2.1.0+incompatible",
    "v1.0.0-rc.1",
    "a".repeat(39) + "1",
  ]) {
    assert.ok(isExactVersion(good), `${good} should be exact`);
  }

  for (const bad of ["latest", "master", "main", "upgrade", "patch", "v1", "v1.7", "", "HEAD"]) {
    assert.ok(!isExactVersion(bad), `${bad} should not be exact`);
  }
});

test("a bare module path is denied — SPEC 10.2", () => {
  const analysis = analyzeCommand("go get github.com/foo/bar");
  assert.equal(analysis.classification, "THIRD_PARTY_MUTATION");
  assert.ok(denied(analysis));
  assert.deepEqual(classes(analysis), ["DependencyAdd"]);
});

test("@latest is denied for both get and install — SPEC 10.2", () => {
  assert.ok(denied(analyzeCommand("go get github.com/foo/bar@latest")));
  assert.ok(denied(analyzeCommand("go install example.com/tool@latest")));
});

test("other floating references are denied", () => {
  for (const version of ["master", "main", "upgrade", "patch", "v1", "my-branch"]) {
    assert.ok(
      denied(analyzeCommand(`go get github.com/foo/bar@${version}`)),
      `@${version} should be denied`,
    );
  }
});

// NEGATIVE CASE: legitimate pinned work must proceed into the pipeline.
test("an exact version is NOT denied and enters the trust pipeline", () => {
  const analysis = analyzeCommand("go get github.com/foo/bar@v1.7.2");
  assert.equal(analysis.classification, "THIRD_PARTY_MUTATION");
  assert.ok(!denied(analysis), "an exact version must not be denied outright");
  const [op] = analysis.operations;
  assert.equal(op?.eventClass, "DependencyAdd");
  assert.equal(op?.artifact, "github.com/foo/bar");
  assert.equal(op?.version, "v1.7.2");
});

test("go get -u has no exact version to approve and is denied", () => {
  assert.ok(denied(analyzeCommand("go get -u github.com/foo/bar")));
  assert.ok(denied(analyzeCommand("go get -u ./...")));
  assert.ok(denied(analyzeCommand("go get -u all")));
});

test("go get with no arguments resolves versions dynamically and is denied", () => {
  assert.ok(denied(analyzeCommand("go get")));
});

test("go get module@none removes a requirement rather than adding one", () => {
  const analysis = analyzeCommand("go get github.com/foo/bar@none");
  assert.deepEqual(classes(analysis), ["DependencyRemove"]);
  assert.ok(!denied(analysis));
});

test("a version from an unresolved expansion cannot be proven exact, so it is denied", () => {
  assert.ok(denied(analyzeCommand("go get github.com/foo/bar@$VERSION")));
});

// ---------------------------------------------------------------------------
// Checksum integrity (SPEC 10.3, invariant 18)
// ---------------------------------------------------------------------------

test("GOSUMDB=off is denied wherever it is set", () => {
  for (const command of [
    "GOSUMDB=off go test ./...",
    "go env -w GOSUMDB=off",
    "env GOSUMDB=off go build ./...",
    "GOSUMDB=off make build",
  ]) {
    const analysis = analyzeCommand(command);
    assert.ok(denied(analysis), command);
    assert.ok(classes(analysis).includes("ChecksumBypass"), command);
  }
});

test("other checksum-weakening variables are denied", () => {
  for (const command of [
    "GONOSUMDB=* go build ./...",
    "GONOSUMCHECK=1 go build ./...",
    "GOFLAGS=-insecure go build ./...",
    "GOINSECURE=example.com go build ./...",
    "GOPRIVATE=* go build ./...",
  ]) {
    assert.ok(denied(analyzeCommand(command)), command);
  }
});

// NEGATIVE CASE: GOPRIVATE has a legitimate use for internal modules.
test("a scoped GOPRIVATE is not treated as a checksum bypass", () => {
  const analysis = analyzeCommand("GOPRIVATE=github.com/mycorp/* go build ./...");
  assert.ok(!denied(analysis), "a scoped GOPRIVATE is normal internal-module usage");
});

test("go env without -w is a read and is irrelevant", () => {
  const analysis = analyzeCommand("go env GOPATH");
  assert.equal(analysis.classification, "SUPPLY_CHAIN_IRRELEVANT");
});

test("go env -w of an unrelated variable is a gate change, not a bypass", () => {
  const analysis = analyzeCommand("go env -w GOPROXY=https://proxy.example.com");
  assert.deepEqual(classes(analysis), ["SecurityGateChange"]);
  assert.ok(!denied(analysis));
});

// ---------------------------------------------------------------------------
// Third-party execution and module operations
// ---------------------------------------------------------------------------

test("go run module@version is third-party execution", () => {
  const analysis = analyzeCommand("go run example.com/tool@v1.2.3");
  assert.deepEqual(classes(analysis), ["ThirdPartyExecution"]);
  assert.ok(!denied(analysis));
  assert.ok(denied(analyzeCommand("go run example.com/tool@latest")));
});

// NEGATIVE CASE: running local code is normal development.
test("go run on a local path produces no event", () => {
  for (const command of ["go run .", "go run ./cmd/server", "go run ./..."]) {
    assert.deepEqual(analyzeCommand(command).operations, [], command);
  }
});

test("go mod subcommands map to fetch and lockfile events", () => {
  assert.deepEqual(classes(analyzeCommand("go mod download")), ["DependencyFetch"]);
  assert.deepEqual(classes(analyzeCommand("go mod tidy")), ["LockfileMutation"]);
  assert.deepEqual(classes(analyzeCommand("go mod vendor")), ["DependencyFetch"]);
  assert.deepEqual(analyzeCommand("go mod verify").operations, []);
  assert.deepEqual(analyzeCommand("go mod init example.com/x").operations, []);
});

test("go mod edit is a manifest mutation", () => {
  assert.deepEqual(classes(analyzeCommand("go mod edit -require=github.com/foo/bar@v1.2.3")), [
    "DependencyAdd",
  ]);
  assert.ok(denied(analyzeCommand("go mod edit -require=github.com/foo/bar@latest")));
  assert.deepEqual(classes(analyzeCommand("go mod edit -replace=a.com/b=c.com/d@v1.0.0")), [
    "DependencyReplace",
  ]);
  assert.deepEqual(classes(analyzeCommand("go mod edit -droprequire=github.com/foo/bar")), [
    "DependencyRemove",
  ]);
});

test("go work edit -replace is a replace event", () => {
  assert.deepEqual(classes(analyzeCommand("go work edit -replace=a.com/b=../local")), [
    "DependencyReplace",
  ]);
});

test("go install of a local package is not a remote tool install", () => {
  const analysis = analyzeCommand("go install ./cmd/tool");
  assert.ok(!denied(analysis));
  assert.equal(analysis.classification, "THIRD_PARTY_CAPABLE");
});

// ---------------------------------------------------------------------------
// Ordinary development must stay out of the way (SPEC 5.1, 2.2)
// ---------------------------------------------------------------------------

test("build and test are third-party-capable, not mutations", () => {
  for (const command of ["go build ./...", "go test ./...", "go vet ./...", "go list -m all"]) {
    const analysis = analyzeCommand(command);
    assert.equal(analysis.classification, "THIRD_PARTY_CAPABLE", command);
    assert.deepEqual(analysis.operations, [], command);
  }
});

test("inert go subcommands and non-go commands are irrelevant", () => {
  for (const command of [
    "go version",
    "go doc fmt",
    "ls -la",
    "git status",
    "cat README.md",
    "grep -r foo src/",
  ]) {
    assert.equal(
      analyzeCommand(command).classification,
      "SUPPLY_CHAIN_IRRELEVANT",
      command,
    );
  }
});

// REGRESSION: `gofmt` starts with "go" but is a different program.
test("gofmt is not go", () => {
  assert.equal(analyzeCommand("gofmt -w .").classification, "SUPPLY_CHAIN_IRRELEVANT");
  assert.equal(analyzeCommand("gofmt -l ./src").classification, "SUPPLY_CHAIN_IRRELEVANT");
});

test("a word containing 'go' does not trigger the safety net", () => {
  for (const command of [
    "cd gopath && ls",
    "echo 'go for it'",
    "cat django/settings.py",
    "ls mongodb/",
  ]) {
    assert.equal(
      analyzeCommand(command).classification,
      "SUPPLY_CHAIN_IRRELEVANT",
      command,
    );
  }
});
