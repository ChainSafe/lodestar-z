import {describe, expect, it} from "vitest";

const bindings = await import("../src/index.ts");
const {computeEpochAtSlot, computeStartSlotAtEpoch, computeCheckpointEpochAtStateSlot, computeEndSlotAtEpoch, computeActivationExitEpoch} = bindings.default.epoch;

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

  describe("computeStartSlotAtEpoch", () => {
    it("should return slot 0 for epoch 0", () => {
      expect(computeStartSlotAtEpoch(0)).toBe(0);
    });

    it("should return slot 32 for epoch 1", () => {
      expect(computeStartSlotAtEpoch(1)).toBe(SLOTS_PER_EPOCH);
    });

    it("should return slot 64 for epoch 2", () => {
      expect(computeStartSlotAtEpoch(2)).toBe(SLOTS_PER_EPOCH * 2);
    });

    it("should handle large epoch numbers", () => {
      const largeEpoch = 100000;
      expect(computeStartSlotAtEpoch(largeEpoch)).toBe(largeEpoch * SLOTS_PER_EPOCH);
    });

    it("should throw for negative epoch -1", () => {
      expect(() => computeStartSlotAtEpoch(-1)).toThrow("InvalidEpoch");
    });

    it("should be inverse of computeEpochAtSlot", () => {
      for (const epoch of [0, 1, 10, 100, 1000]) {
        const slot = computeStartSlotAtEpoch(epoch);
        expect(computeEpochAtSlot(slot)).toBe(epoch);
      }
    });
  });

  describe("computeCheckpointEpochAtStateSlot", () => {
    it("should return same epoch at start slot, next epoch otherwise", () => {
      expect(computeCheckpointEpochAtStateSlot(0)).toBe(0);
      expect(computeCheckpointEpochAtStateSlot(1)).toBe(1);
      expect(computeCheckpointEpochAtStateSlot(SLOTS_PER_EPOCH)).toBe(1);
    });

    it("should throw for negative slot", () => {
      expect(() => computeCheckpointEpochAtStateSlot(-1)).toThrow("InvalidSlot");
    });
  });

  describe("computeEndSlotAtEpoch", () => {
    it("should return last slot of epoch", () => {
      expect(computeEndSlotAtEpoch(0)).toBe(SLOTS_PER_EPOCH - 1);
      expect(computeEndSlotAtEpoch(1)).toBe(SLOTS_PER_EPOCH * 2 - 1);
    });

    it("should throw for negative epoch", () => {
      expect(() => computeEndSlotAtEpoch(-1)).toThrow("InvalidEpoch");
    });
  });

  describe("computeActivationExitEpoch", () => {
    it("should return epoch + 5 for mainnet", () => {
      expect(computeActivationExitEpoch(0)).toBe(5);
      expect(computeActivationExitEpoch(10)).toBe(15);
    });

    it("should throw for negative epoch", () => {
      expect(() => computeActivationExitEpoch(-1)).toThrow("InvalidEpoch");
    });
  });
});
