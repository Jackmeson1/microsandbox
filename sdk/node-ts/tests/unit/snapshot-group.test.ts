import { describe, expect, it, vi } from "vitest";
import { Snapshot, snapshotCreateResult } from "../../dist/snapshot-group.js";
import { napi } from "../../dist/internal/napi.js";

vi.mock("../../dist/internal/napi.js", () => ({
  napi: { SnapshotGroup: { get: vi.fn(), list: vi.fn() }, Snapshot: { groupHead: vi.fn() } },
}));
vi.mock("../../dist/sandbox.js", () => ({ Sandbox: class {} }));

function group(overrides: Record<string, unknown> = {}) {
  return {
    name: "history",
    head: vi.fn().mockResolvedValue(undefined),
    setHead: vi.fn(),
    clearHead: vi.fn().mockResolvedValue({ group: "history", previous: "old", head: undefined, changed: true, reason: "cleared" }),
    checkpoint: vi.fn(),
    ...overrides,
  };
}

describe("group and checkpoint separation", () => {
  it("opens a headless group without manufacturing a checkpoint", async () => {
    const native = group();
    vi.mocked(napi.SnapshotGroup.get).mockResolvedValue(native as never);
    const history = await Snapshot.get("history");
    expect(history.name).toBe("history");
    expect(await history.head()).toBeNull();
    expect(await history.clearHead()).toEqual({ group: "history", previous: "old", head: null, changed: true, reason: "cleared" });
  });

  it("returns the capture's checkpoint even when the current head has moved", async () => {
    const native = group({
      head: vi.fn().mockResolvedValue({ id: "later" }),
      checkpoint: vi.fn().mockResolvedValue({
        checkpoint: { id: "captured" },
        headUpdate: { group: "history", previous: undefined, head: "captured", changed: true, reason: "initialized" },
      }),
    });
    const history = new Snapshot(native as never);
    const captured = await history.checkpointWith(options => options.name("base").recordIntegrity());
    expect(captured.checkpoint.id).toBe("captured");
    expect(captured.headUpdate.head).toBe("captured");
    expect(captured.headUpdate.previous).toBeNull();
    expect(native.head).not.toHaveBeenCalled();
    expect(native.checkpoint).toHaveBeenCalledWith({ name: "base", recordIntegrity: true });
  });

  it("preserves initial-capture identity without rereading the group", () => {
    const native = group();
    const result = snapshotCreateResult({
      snapshot: native,
      checkpoint: { id: "initial" },
      headUpdate: { group: "history", previous: null, head: "initial", reason: "initialized", changed: true },
    } as never);
    expect(result.snapshot.name).toBe("history");
    expect(result.checkpoint.id).toBe("initial");
    expect(native.head).not.toHaveBeenCalled();
  });
});
