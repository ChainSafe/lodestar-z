// Benchmarks the zig swapOrNotShuffle binding against the Rust-based
// @chainsafe/swap-or-not-shuffle npm package on identical inputs.
import crypto from "node:crypto";
import {bench, describe} from "@chainsafe/benchmark";
import * as reference from "@chainsafe/swap-or-not-shuffle";

const bindings = await import("../src/index.js");
const shuffle = bindings.default.shuffle;

const seed = new Uint8Array(crypto.randomBytes(32));
const rounds = reference.SHUFFLE_ROUNDS_MAINNET;

function getInputArray(count: number): Uint32Array {
  return Uint32Array.from(Array.from({length: count}, (_, i) => i));
}

describe("shuffleList", () => {
  for (const validatorCount of [100_000, 2_000_000]) {
    const input = getInputArray(validatorCount);

    bench({
      fn: () => {
        shuffle.unshuffleList(input, seed, rounds);
      },
      id: `zig unshuffleList - ${validatorCount} indices`,
    });

    bench({
      fn: () => {
        reference.unshuffleList(input, seed, rounds);
      },
      id: `rust unshuffleList - ${validatorCount} indices`,
    });

    bench({
      fn: async () => {
        await shuffle.asyncUnshuffleList(input, seed, rounds);
      },
      id: `zig asyncUnshuffleList - ${validatorCount} indices`,
    });

    bench({
      fn: async () => {
        await reference.asyncUnshuffleList(input, seed, rounds);
      },
      id: `rust asyncUnshuffleList - ${validatorCount} indices`,
    });
  }
});

describe("committee indices", () => {
  const vc = 1_000_000;
  const activeIndices = getInputArray(vc);
  const effectiveBalanceIncrements = new Uint16Array(vc);
  for (let i = 0; i < vc; i++) {
    effectiveBalanceIncrements[i] = 32 + 32 * (i % 64);
  }
  const MAX_EFFECTIVE_BALANCE_ELECTRA = 2_048_000_000_000;
  const EFFECTIVE_BALANCE_INCREMENT = 1_000_000_000;
  const SYNC_COMMITTEE_SIZE = 512;

  bench({
    fn: () => {
      shuffle.computeSyncCommitteeIndicesElectra(
        seed,
        activeIndices,
        effectiveBalanceIncrements,
        SYNC_COMMITTEE_SIZE,
        MAX_EFFECTIVE_BALANCE_ELECTRA,
        EFFECTIVE_BALANCE_INCREMENT,
        rounds
      );
    },
    id: `zig computeSyncCommitteeIndicesElectra - ${vc} indices`,
  });

  bench({
    fn: () => {
      reference.computeSyncCommitteeIndicesElectra(
        seed,
        activeIndices,
        effectiveBalanceIncrements,
        SYNC_COMMITTEE_SIZE,
        MAX_EFFECTIVE_BALANCE_ELECTRA,
        EFFECTIVE_BALANCE_INCREMENT,
        rounds
      );
    },
    id: `rust computeSyncCommitteeIndicesElectra - ${vc} indices`,
  });

  bench({
    fn: () => {
      shuffle.computeProposerIndexElectra(
        seed,
        activeIndices,
        effectiveBalanceIncrements,
        MAX_EFFECTIVE_BALANCE_ELECTRA,
        EFFECTIVE_BALANCE_INCREMENT,
        rounds
      );
    },
    id: `zig computeProposerIndexElectra - ${vc} indices`,
  });

  bench({
    fn: () => {
      reference.computeProposerIndexElectra(
        seed,
        activeIndices,
        effectiveBalanceIncrements,
        MAX_EFFECTIVE_BALANCE_ELECTRA,
        EFFECTIVE_BALANCE_INCREMENT,
        rounds
      );
    },
    id: `rust computeProposerIndexElectra - ${vc} indices`,
  });
});
