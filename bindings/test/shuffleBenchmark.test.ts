import {beforeAll, describe, expect, it, vi} from "vitest";
import {deterministicBenchmarkSeed} from "../perf/benchmarkSeed.js";
import * as shuffle from "../src/shuffle.js";

const cases = vi.hoisted(() => new Map<string, () => unknown>());
vi.mock("@chainsafe/benchmark", () => ({
  bench: ({id, fn}: {id: string; fn: () => unknown}) => {
    if (cases.has(id)) throw new Error(`Duplicate benchmark ID: ${id}`);
    cases.set(id, fn);
  },
  describe: (_name: string, collect: () => void) => collect(),
}));

beforeAll(async () => {
  await import("../perf/shuffle.test.js");
});

describe("sync committee benchmark workloads", () => {
  it.each([16_384, 250_000, 262_144, 1_000_000])("registers a deterministic 32 ETH case for %i validators", (size) => {
    const id = `zig - computeSyncCommitteeIndices - ${size} indices - 32 ETH`;
    expect(cases.has(id)).toBe(true);
    const compute = vi.spyOn(shuffle, "computeSyncCommitteeIndices");
    try {
      cases.get(id)?.();
      expect(compute).toHaveBeenCalledTimes(1);
      const [seed, indices, balances, byteCount, committeeSize] = compute.mock.calls[0];
      expect(seed).toEqual(deterministicBenchmarkSeed(`committee-indices:${size}`));
      expect(indices.length).toBe(size);
      expect(indices.every((index, position) => index === position)).toBe(true);
      expect(balances.length).toBe(size);
      expect(balances.every((balance) => balance === 32)).toBe(true);
      expect(byteCount).toBe(2);
      expect(committeeSize).toBe(512);
      expect(compute.mock.results[0].value).toHaveLength(512);
    } finally {
      compute.mockRestore();
    }
  });

  it("retains every existing benchmark ID", () => {
    const operations = [
      "JS  - unshuffleList",
      "zig - unshuffleList",
      "JS  - computeSyncCommitteeIndicesElectra",
      "zig - computeSyncCommitteeIndices",
      "zig - computeProposerIndex",
      "JS  - computePtcIndices",
      "zig - computePtcIndices",
    ];
    for (const size of [16_384, 250_000, 1_000_000]) {
      for (const operation of operations) expect(cases.has(`${operation} - ${size} indices`)).toBe(true);
    }
    for (const size of [250_000, 1_000_000]) {
      for (const implementation of ["JS ", "zig"]) {
        expect(cases.has(`${implementation} - computePtcIndicesForEpoch - ${size} validators`)).toBe(true);
      }
    }
  });
});
