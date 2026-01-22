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

  it("should compute proposer index for all forks", () => {
    const testCases = [
      {expected: 789, forks: ["phase0", "altair", "bellatrix", "capella", "deneb"] as const},
      {expected: 161, forks: ["electra", "fulu"] as const},
    ];

    for (const {forks, expected} of testCases) {
      for (const fork of forks) {
        const result = bindings.computeProposerIndex(fork, effectiveBalanceIncrements, indices, seed);
        expect(result).toBe(expected);
      }
    }
  });

  it("should throw on invalid seed length", () => {
    const shortSeed = new Uint8Array(16);
    expect(() => bindings.computeProposerIndex("phase0", effectiveBalanceIncrements, indices, shortSeed)).toThrow(
      "InvalidSeedLength"
    );
  });
});
