import {describe, expect, it} from "vitest";
import bindings from "../src/index.ts";

describe("computeProposerIndex", () => {
  const seed = new Uint8Array(32).fill(1);
  const indexCount = 1000;

  const indices = new Uint32Array(indexCount);
  for (let i = 0; i < indexCount; i++) {
    indices[i] = i;
  }

  const effectiveBalanceIncrements = new Uint16Array(indexCount);
  for (let i = 0; i < indexCount; i++) {
    effectiveBalanceIncrements[i] = 32 + 32 * (i % 64);
  }

  it("should compute proposer index for phase0", () => {
    const result = bindings.computeProposerIndex(
      "phase0",
      effectiveBalanceIncrements,
      indices,
      seed
    );
    expect(result).toBe(789);
  });

  it("should compute proposer index for electra", () => {
    const result = bindings.computeProposerIndex(
      "electra",
      effectiveBalanceIncrements,
      indices,
      seed
    );
    expect(result).toBe(161);
  });

  it("should handle pre-electra forks the same as phase0", () => {
    const forks = ["phase0", "altair", "bellatrix", "capella", "deneb"] as const;
    const expected = 789;

    for (const fork of forks) {
      const result = bindings.computeProposerIndex(
        fork,
        effectiveBalanceIncrements,
        indices,
        seed
      );
      expect(result).toBe(expected);
    }
  });

  it("should handle electra+ forks the same", () => {
    const forks = ["electra", "fulu"] as const;
    const expected = 161;

    for (const fork of forks) {
      const result = bindings.computeProposerIndex(
        fork,
        effectiveBalanceIncrements,
        indices,
        seed
      );
      expect(result).toBe(expected);
    }
  });

  it("should throw on invalid seed length", () => {
    const shortSeed = new Uint8Array(16);
    expect(() =>
      bindings.computeProposerIndex("phase0", effectiveBalanceIncrements, indices, shortSeed)
    ).toThrow("InvalidSeedLength");
  });
});
