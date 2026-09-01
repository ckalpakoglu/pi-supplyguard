/**
 * Minimal hand-written ambient declarations for the Node built-ins we use.
 *
 * Why this file exists
 * --------------------
 * `@types/node` is a dependency, and this commit is a deliberately audited
 * dependency baseline (yaml + typescript only). Rather than add an unapproved
 * package to make the type-check gate pass, we declare only the two built-in
 * surfaces the placeholder test touches.
 *
 * THIS IS A STOPGAP, NOT A STRATEGY. SupplyGuard will need real `node:fs`,
 * `node:path`, `node:crypto`, `node:child_process` and `node:process` types as
 * soon as M1 work starts. Hand-writing those is unsustainable and would itself
 * become a correctness risk. Recommend a human-approved, exact-pinned
 * `@types/node` devDependency before W1 begins, at which point this file should
 * be deleted.
 */
declare module "node:test" {
  export function test(
    name: string,
    fn: () => void | Promise<void>,
  ): void;
}

declare module "node:assert/strict" {
  interface AssertStrict {
    equal(actual: unknown, expected: unknown, message?: string): void;
  }
  const assert: AssertStrict;
  export default assert;
}
