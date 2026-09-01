import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

/**
 * pi-supplyguard
 *
 * Baseline Pi extension entrypoint.
 *
 * Enforcement is intentionally not implemented here yet.
 * M1 will introduce classification, profiles, decisions,
 * configuration, audit, and user-facing controls.
 */
export default function supplyguard(pi: ExtensionAPI): void {
  pi.on("tool_call", async () => {
    // Baseline only: allow normal Pi behavior.
    return undefined;
  });
}
