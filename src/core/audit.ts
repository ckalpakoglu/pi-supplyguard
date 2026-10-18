/**
 * Append-only audit log (SPEC 18).
 *
 * Privacy rules (SPEC 18.3) are enforced here, not by convention elsewhere:
 * - no credentials, tokens or secrets;
 * - no raw environment dumps;
 * - values are redacted by key name AND by shape before they are written.
 *
 * The log is JSONL: one record per line, appended, never rewritten.
 */

import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";

import type { Decision, Finding } from "./decisions.ts";
import type { SupplyChainEventClass, ToolCallClassification } from "./events.ts";
import type { Profile } from "./profiles.ts";

export const REDACTED = "[redacted]";

/**
 * Key names whose values are never written, whatever they contain.
 * Matched case-insensitively against the key with separators removed.
 */
const SENSITIVE_KEY_FRAGMENTS = [
  "token",
  "secret",
  "password",
  "passwd",
  "pwd",
  "apikey",
  "authorization",
  "auth",
  "credential",
  "cookie",
  "privatekey",
  "publickey",
  "accesskey",
  "secretkey",
  "sessionkey",
  "bearer",
  "signature",
  "environ",
  "npmrc",
  "netrc",
] as const;

/** Whole-key matches for containers that would otherwise leak wholesale. */
const SENSITIVE_KEY_EXACT = new Set(["env", "environment", "processenv", "headers"]);

/**
 * Value shapes that are secrets regardless of the key they arrived under.
 * Conservative: a match redacts the ENTIRE string, never a substring.
 */
const SECRET_VALUE_PATTERNS: readonly RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bgh[pousr]_[A-Za-z0-9]{16,}/,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/,
  /\bsk-[A-Za-z0-9_-]{16,}/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bAIza[0-9A-Za-z_-]{20,}/,
  /\bsktok_[A-Za-z0-9]{16,}/,
  /\b[Bb]earer\s+[A-Za-z0-9._~+/-]{16,}=*/,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
];

const MAX_DEPTH = 6;
const MAX_STRING_LENGTH = 2000;
const MAX_ARRAY_ITEMS = 50;
const MAX_OBJECT_KEYS = 50;

function isSensitiveKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
  if (SENSITIVE_KEY_EXACT.has(normalized)) return true;
  return SENSITIVE_KEY_FRAGMENTS.some((fragment) => normalized.includes(fragment));
}

function redactString(value: string): string {
  for (const pattern of SECRET_VALUE_PATTERNS) {
    if (pattern.test(value)) return REDACTED;
  }
  return value.length > MAX_STRING_LENGTH
    ? `${value.slice(0, MAX_STRING_LENGTH)}…[truncated]`
    : value;
}

/**
 * Deep-redact an arbitrary value before it is written anywhere durable.
 *
 * Anything unrepresentable in JSON (functions, symbols, class instances with
 * behavior) is dropped rather than coerced: audit records must stay inert data.
 */
export function redact(value: unknown, depth = 0): unknown {
  if (value === null) return null;

  const type = typeof value;
  if (type === "string") return redactString(value as string);
  if (type === "number") return Number.isFinite(value as number) ? value : null;
  if (type === "boolean") return value;
  if (type === "bigint") return (value as bigint).toString();
  if (type === "undefined" || type === "function" || type === "symbol") return undefined;

  if (depth >= MAX_DEPTH) return "[depth-limited]";

  if (Array.isArray(value)) {
    const items = value.slice(0, MAX_ARRAY_ITEMS).map((item) => redact(item, depth + 1));
    if (value.length > MAX_ARRAY_ITEMS) items.push("[truncated]");
    return items;
  }

  if (value instanceof Date) return value.toISOString();
  if (value instanceof Error) return `${value.name}: ${redactString(value.message)}`;
  // `Object.entries` on these is empty, so they would serialize as `{}` --
  // indistinguishable from "there was nothing here". Say so instead.
  if (value instanceof Map) return `[Map(${value.size})]`;
  if (value instanceof Set) return `[Set(${value.size})]`;

  if (type === "object") {
    const out: Record<string, unknown> = {};
    let count = 0;
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (count >= MAX_OBJECT_KEYS) {
        out["[truncated]"] = true;
        break;
      }
      count += 1;
      if (isSensitiveKey(key)) {
        out[key] = REDACTED;
        continue;
      }
      const redacted = redact(item, depth + 1);
      if (redacted !== undefined) out[key] = redacted;
    }
    return out;
  }

  return undefined;
}

export const AUDIT_RECORD_KINDS = [
  "tool-call",
  "config",
  "command",
  // An ask-once project question and how it was answered (SPEC 9.2, 13.3).
  "project-decision",
  // The agent's stated rationale for a dependency (SPEC 11.2).
  "justification",
  // A tool ran with different input than SupplyGuard evaluated (KNOWN-GAPS
  // 1.10): a later handler revised it after the gate. Audited, not prevented.
  "input-revision",
  // A tracked file changed while no tool call was executing (M12 watch).
  "out-of-band-write",
] as const;

export type AuditRecordKind = (typeof AUDIT_RECORD_KINDS)[number];

/** SPEC 18.1 -- audit record. Fields are non-secret metadata only. */
export interface AuditRecord {
  readonly timestamp: string;
  readonly kind: AuditRecordKind;
  readonly profile: Profile;
  readonly session: string;
  readonly cwd: string;
  readonly branch?: string;
  /** Interactive capability at decision time; part of fail-closed evidence. */
  readonly headless: boolean;
  readonly tool?: string;
  readonly classification?: ToolCallClassification;
  readonly event?: SupplyChainEventClass;
  readonly ecosystem?: string;
  readonly artifact?: string;
  readonly version?: string;
  readonly decision?: Decision;
  readonly findings?: readonly Finding[];
  readonly approval?: {
    readonly required: boolean;
    readonly granted: boolean;
    readonly reason: string;
  };
  /** A scoped one-shot override and the reason a human gave for it (SPEC 17.2). */
  readonly override?: {
    readonly offered: boolean;
    readonly granted: boolean;
    readonly reason: string;
    readonly justification?: string;
  };
  readonly message?: string;
  readonly notes?: readonly string[];
}

export type AuditSink = (record: AuditRecord) => Promise<void>;

/** A sink that discards records. Used when auditing is disabled. */
export const NULL_AUDIT_SINK: AuditSink = async () => {};

/**
 * Append one record as a single JSONL line.
 *
 * The directory is created with 0o700 and the log with 0o600: audit evidence
 * is not world-readable.
 */
export async function appendAuditRecord(path: string, record: AuditRecord): Promise<void> {
  const safe = redact(record) as Record<string, unknown>;
  const line = `${JSON.stringify(safe)}\n`;
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await appendFile(path, line, { encoding: "utf8", mode: 0o600 });
}

export function createAuditSink(path: string): AuditSink {
  return (record) => appendAuditRecord(path, record);
}

/**
 * Best-effort current git branch, read from `.git` without spawning anything.
 *
 * Returns `undefined` when it cannot be determined; SupplyGuard never invents
 * repository facts it could not read.
 */
export async function detectGitBranch(repoRoot: string): Promise<string | undefined> {
  const gitPath = join(repoRoot, ".git");
  let gitDir = gitPath;

  try {
    const raw = await readFile(gitPath, "utf8");
    const match = /^gitdir:\s*(.+)$/m.exec(raw);
    if (match?.[1] === undefined) return undefined;
    const declared = match[1].trim();
    gitDir = isAbsolute(declared) ? declared : join(repoRoot, declared);
  } catch {
    // `.git` is a directory (EISDIR) or absent (ENOENT); fall through.
  }

  try {
    const head = await readFile(join(gitDir, "HEAD"), "utf8");
    const ref = /^ref:\s*refs\/heads\/(.+)$/m.exec(head);
    if (ref?.[1] !== undefined) return ref[1].trim();
    const detached = head.trim();
    return /^[0-9a-f]{7,40}$/.test(detached) ? `detached@${detached.slice(0, 12)}` : undefined;
  } catch {
    return undefined;
  }
}
