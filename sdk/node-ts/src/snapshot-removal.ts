import type { HeadUpdate } from "./snapshot.js";

/** Facts captured by one exact checkpoint removal under storage ownership. */
export interface CheckpointRemoveResult {
  readonly id: string;
  readonly headUpdate: HeadUpdate | null;
  readonly warnings: readonly string[];
}

/** @internal Parse both successful results and committed-removal recovery errors. */
export function parseCheckpointRemoval(value: unknown): CheckpointRemoveResult {
  if (!value || typeof value !== "object") throw new TypeError("Invalid checkpoint removal result");
  const record = value as Record<string, unknown>;
  const head = record.head_update as Record<string, unknown> | null;
  if (typeof record.id !== "string" || !Array.isArray(record.warnings) ||
      !record.warnings.every((warning) => typeof warning === "string")) {
    throw new TypeError("Invalid checkpoint removal result");
  }
  if (head !== null && (!head || typeof head.group !== "string" ||
      !(head.previous === null || typeof head.previous === "string") ||
      !(head.head === null || typeof head.head === "string") ||
      typeof head.reason !== "string" || typeof head.changed !== "boolean")) {
    throw new TypeError("Invalid checkpoint removal head outcome");
  }
  return { id: record.id, headUpdate: head as HeadUpdate | null, warnings: record.warnings as string[] };
}
