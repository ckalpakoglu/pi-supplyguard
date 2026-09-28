/**
 * Local artifact-content scanning (M10, PLAN-ZERO-DAY P1).
 *
 * The one zero-day question no database can answer is "what does this
 * dependency's code actually do?". This module answers the cheap half of it
 * locally: deterministic, offline heuristics over the module's own source,
 * reporting file and line so the human reads code instead of a score.
 *
 * It is honest about being a heuristic for lazy and templated malware — which
 * the incident record says most real attacks are — and every rule carries a
 * false-positive corpus in `test/analyzers/content.test.ts`. A determined
 * author defeats it; that is what vendor quarantine and the hermetic build
 * gate (M11) are for. Defense in depth, not detection perfection.
 */

import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";

/** One scanner verdict: where, and what shape was recognized. */
export interface ContentFinding {
  readonly rule: string;
  readonly file: string;
  readonly line: number;
  readonly message: string;
}

/** Bounds: a scanner that reads unboundedly is a denial-of-service tool. */
const MAX_FILES = 200;
const MAX_FILE_BYTES = 256 * 1024;
const MAX_TOTAL_BYTES = 2 * 1024 * 1024;
const ENCODED_BLOB = /[A-Za-z0-9+/]{512,}={0,2}|[0-9a-fA-F]{512,}/;
const EGRESS = /\bhttp\.(Get|Post|Head|Do|NewRequest|Client)|\bnet\.(Dial|DialTCP)\b/;
const EXEC = /\bexec\.Command(?:Context)?\b/;
const GO_GENERATE = /^\s*\/\/go:generate\b/;

async function isDirectory(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isDirectory();
  } catch {
    return false;
  }
}

/**
 * Where can this module's source be read locally?
 *
 * `vendor/<path>` when the repository vendors (no version in the path), or the
 * module cache (`$GOMODCACHE`, else `$GOPATH/pkg/mod`, else `~/go/pkg/mod`)
 * which lays out `<path>@<version>`. Both are offline reads; nothing is sent
 * anywhere. `undefined` means the source is not locally resolvable and the
 * artifact's content is uninspectable here.
 */
export async function locateModuleSource(
  repoRoot: string,
  artifact: string,
  version: string | undefined,
  env: Readonly<Record<string, string | undefined>> = {},
): Promise<{ readonly root: string; readonly source: "vendor" | "module-cache" } | undefined> {
  if (artifact === "") return undefined;

  const vendorRoot = join(repoRoot, "vendor", artifact);
  if (await isDirectory(vendorRoot)) return { root: vendorRoot, source: "vendor" };

  if (version !== undefined && version !== "") {
    const cache = env.GOMODCACHE ?? join(env.GOPATH ?? join(homedir(), "go"), "pkg", "mod");
    const cached = join(cache, `${artifact}@${version}`);
    if (await isDirectory(cached)) return { root: cached, source: "module-cache" };
  }

  return undefined;
}

/** Walk `root` collecting `*.go` files within the read budget. */
async function collectGoFiles(root: string): Promise<string[]> {
  const files: string[] = [];
  const queue: string[] = [root];

  while (queue.length > 0 && files.length < MAX_FILES) {
    const dir = queue.shift();
    if (dir === undefined) break;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (files.length >= MAX_FILES) break;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        queue.push(full);
      } else if (entry.isFile() && entry.name.endsWith(".go")) {
        files.push(full);
      }
    }
  }

  return files.sort();
}

/** Body of the first `func init()` in `text`, with its start offset. */
function initBody(text: string): { readonly body: string; readonly start: number } | undefined {
  const match = /(^|\n)func init\(\)\s*\{/.exec(text);
  if (match === null) return undefined;
  let depth = 0;
  const start = match.index + match[0].length;
  for (let i = start - 1; i < text.length; i += 1) {
    const char = text[i];
    if (char === "{") depth += 1;
    else if (char === "}") {
      depth -= 1;
      if (depth === 0) return { body: text.slice(start, i), start };
    }
  }
  return { body: text.slice(start), start };
}

/** `import "C"` preamble in the same file as the needle. */
function importsCgoWith(text: string, needle: RegExp): boolean {
  const preamble = /import\s+"C"/.test(text);
  return preamble && needle.test(text);
}

/**
 * Scan one module's source. Never throws: an unreadable tree simply yields
 * no findings, and the caller decides what "uninspected" means.
 */
export async function scanModuleSource(root: string): Promise<readonly ContentFinding[]> {
  const findings: ContentFinding[] = [];
  let budget = MAX_TOTAL_BYTES;

  for (const file of await collectGoFiles(root)) {
    let text: string;
    try {
      const handle = await stat(file);
      if (handle.size > MAX_FILE_BYTES) continue;
      budget -= handle.size;
      if (budget < 0) break;
      text = await readFile(file, "utf8");
    } catch {
      continue;
    }

    const rel = file.slice(root.length + 1);
    const lineOf = (index: number): number => text.slice(0, index).split("\n").length;

    // Code that runs merely because the package is imported.
    const init = initBody(text);
    if (init !== undefined) {
      const egress = EGRESS.exec(init.body);
      if (egress !== null) {
        findings.push({
          rule: "content:init-egress",
          file: rel,
          line: lineOf(init.start + egress.index),
          message: `network call inside func init(): runs at import time, before any code of yours`,
        });
      }
      const exec = EXEC.exec(init.body);
      if (exec !== null) {
        findings.push({
          rule: "content:init-exec",
          file: rel,
          line: lineOf(init.start + exec.index),
          message: `process execution inside func init(): runs at import time, before any code of yours`,
        });
      }
    }

    // Whole-environment capture with an egress call in the same file.
    const environ = /\bos\.Environ\b/.exec(text);
    const envEgress = environ !== null ? EGRESS.exec(text) : null;
    if (environ !== null && envEgress !== null) {
      findings.push({
        rule: "content:env-egress",
        file: rel,
        line: lineOf(environ.index),
        message: `reads the entire process environment alongside a network call in the same file`,
      });
    }

    const blob = ENCODED_BLOB.exec(text);
    if (blob !== null) {
      findings.push({
        rule: "content:encoded-blob",
        file: rel,
        line: lineOf(blob.index),
        message: `${blob[0].length}-character encoded literal: classic payload-concealment shape`,
      });
    }

    if (importsCgoWith(text, /\bdlopen\b/)) {
      findings.push({
        rule: "content:cgo-dlopen",
        file: rel,
        line: 1,
        message: `cgo preamble loads a shared library dynamically (dlopen)`,
      });
    }

    const generate = GO_GENERATE.exec(text);
    if (generate !== null) {
      findings.push({
        rule: "content:generate-directive",
        file: rel,
        line: lineOf(generate.index),
        message: `//go:generate directive inside the dependency: arbitrary command at generate time`,
      });
    }
  }

  return findings;
}

/**
 * Concatenated source of a module for an external analyzer, within the same
 * read budget as the scan. Empty string when nothing could be read.
 */
export async function collectModuleText(root: string, budgetChars = 120_000): Promise<string> {
  const parts: string[] = [];
  let used = 0;
  for (const file of await collectGoFiles(root)) {
    if (used >= budgetChars) break;
    try {
      const info = await stat(file);
      if (info.size > MAX_FILE_BYTES) continue;
      const text = await readFile(file, "utf8");
      parts.push(`--- ${file.slice(root.length + 1)} ---\n${text}`);
      used += text.length;
    } catch {
      continue;
    }
  }
  return parts.join("\n");
}

/** Does `GOPRIVATE`/`GONOPROXY` cover this module? Then it goes nowhere. */
export function isPrivateModule(
  artifact: string,
  env: Readonly<Record<string, string | undefined>> = {},
): boolean {
  const patterns = `${env.GOPRIVATE ?? ""},${env.GONOPROXY ?? ""}`
    .split(",")
    .map((p) => p.trim())
    .filter((p) => p !== "" && p !== "off" && p !== "none");
  return patterns.some((pattern) => {
    const glob = pattern
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*")
      .replace(/\?/g, ".");
    return new RegExp(`^${glob}(/|$)`).test(artifact);
  });
}
