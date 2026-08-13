// Benchmarks the zig `shuffle` binding against the pure-TS reference
// implementation, mirroring the reference repo's perf suite
// (https://github.com/ChainSafe/swap-or-not-shuffle test/perf/*).
import crypto from "node:crypto";
import {bench, describe} from "@chainsafe/benchmark";
import * as referenceImplementation from "../test/referenceImplementation.ts";

const bindings = await import("../src/index.js");
const shuffle = bindings.default.shuffle;

function getInputArray(count: number): Uint32Array {
  return Uint32Array.from(Array.from({length: count}, (_, i) => i));
}

for (const listSize of [16_384, 250_000, 1_000_000]) {
  describe(`shuffle list - ${listSize} indices`, () => {
    const seed = new Uint8Array(32).fill(0xac);
    const indices = getInputArray(listSize);
    const rounds = shuffle.SHUFFLE_ROUNDS_MINIMAL;

    bench({
      fn: () => {
        referenceImplementation.unshuffleList(indices, seed, rounds);
      },
      id: `JS  - unshuffleList - ${listSize} indices`,
    });

    bench({
      fn: () => {
        shuffle.unshuffleList(indices, seed, rounds);
      },
      id: `zig - unshuffleList - ${listSize} indices`,
    });

    bench({
      fn: async () => {
        await shuffle.asyncUnshuffleList(indices, seed, rounds);
      },
      id: `zig - asyncUnshuffleList - ${listSize} indices`,
    });
  });
}

describe("committee indices", () => {
  for (const listSize of [16_384, 250_000, 1_000_000]) {
    const seed = new Uint8Array(crypto.randomBytes(32));
    const activeIndices = getInputArray(listSize);
    const effectiveBalanceIncrements = new Uint16Array(listSize);
    for (let i = 0; i < listSize; i++) {
      effectiveBalanceIncrements[i] = 32 + 32 * (i % 64);
    }
    const {EFFECTIVE_BALANCE_INCREMENT, MAX_EFFECTIVE_BALANCE_ELECTRA, SYNC_COMMITTEE_SIZE, SHUFFLE_ROUND_COUNT} =
      referenceImplementation;

    bench({
      fn: () => {
        referenceImplementation.naiveComputeSyncCommitteeIndicesElectra(
          seed,
          activeIndices,
          effectiveBalanceIncrements
        );
      },
      id: `JS  - computeSyncCommitteeIndicesElectra - ${listSize} indices`,
    });

    bench({
      fn: () => {
        shuffle.computeSyncCommitteeIndicesElectra(
          seed,
          activeIndices,
          effectiveBalanceIncrements,
          SYNC_COMMITTEE_SIZE,
          MAX_EFFECTIVE_BALANCE_ELECTRA,
          EFFECTIVE_BALANCE_INCREMENT,
          SHUFFLE_ROUND_COUNT
        );
      },
      id: `zig - computeSyncCommitteeIndicesElectra - ${listSize} indices`,
    });

    bench({
      fn: () => {
        shuffle.computeProposerIndexElectra(
          seed,
          activeIndices,
          effectiveBalanceIncrements,
          MAX_EFFECTIVE_BALANCE_ELECTRA,
          EFFECTIVE_BALANCE_INCREMENT,
          SHUFFLE_ROUND_COUNT
        );
      },
      id: `zig - computeProposerIndexElectra - ${listSize} indices`,
    });
  }
});
