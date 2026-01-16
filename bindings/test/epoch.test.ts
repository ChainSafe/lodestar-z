import {describe, expect, it} from "vitest";

const bindings = await import("../src/index.ts");
const {computeEpochAtSlot} = bindings.default.epoch;

const SLOTS_PER_EPOCH = 32;

describe("epoch", () => {
  describe("computeEpochAtSlot", () => {
    it("should return epoch 0 for slot 0", () => {
      expect(computeEpochAtSlot(0)).toBe(0);
    });

    it("should return epoch 0 for slot 31 (last slot of epoch 0)", () => {
      expect(computeEpochAtSlot(SLOTS_PER_EPOCH - 1)).toBe(0);
    });

    it("should return epoch 1 for slot 32 (first slot of epoch 1)", () => {
      expect(computeEpochAtSlot(SLOTS_PER_EPOCH)).toBe(1);
    });

    it("should return epoch 2 for slot 64", () => {
      expect(computeEpochAtSlot(SLOTS_PER_EPOCH * 2)).toBe(2);
    });

    it("should handle large slot numbers", () => {
      const largeSlot = 1000000;
      const expectedEpoch = Math.floor(largeSlot / SLOTS_PER_EPOCH);
      expect(computeEpochAtSlot(largeSlot)).toBe(expectedEpoch);
    });

    it("should throw for negative slot -1", () => {
      expect(() => computeEpochAtSlot(-1)).toThrow("InvalidSlot");
    });

  });
});
