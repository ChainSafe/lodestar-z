import {randomBytes} from "node:crypto";
import * as reference from "@chainsafe/swap-or-not-shuffle";
import {describe, expect, it} from "vitest";

const bindings = await import("../src/index.js");
const swapOrNotShuffle = bindings.default.shuffle;

function getInputArray(count: number): Uint32Array {
  return Uint32Array.from(Array.from({length: count}, (_, i) => i));
}

function randomSeed(): {seed: Uint8Array; id: string} {
  const seed = new Uint8Array(randomBytes(32));
  return {id: `seed 0x${Buffer.from(seed).toString("hex")}`, seed};
}

describe("swapOrNotShuffle", () => {
  describe("constants", () => {
    it("should match the reference package", () => {
      expect(swapOrNotShuffle.SHUFFLE_ROUNDS_MAINNET).toEqual(reference.SHUFFLE_ROUNDS_MAINNET);
      expect(swapOrNotShuffle.SHUFFLE_ROUNDS_MINIMAL).toEqual(reference.SHUFFLE_ROUNDS_MINIMAL);
      expect(swapOrNotShuffle.ByteCount).toEqual({...reference.ByteCount});
    });
  });

  describe("shuffleList/unshuffleList", () => {
    it("should throw for invalid seed", () => {
      const input = getInputArray(10);
      let invalidSeed = Buffer.alloc(31, 0xac);
      expect(() => swapOrNotShuffle.unshuffleList(input, invalidSeed, 10)).to.throw(
        "Shuffling seed must be 32 bytes long"
      );
      invalidSeed = Buffer.alloc(33, 0xac);
      expect(() => swapOrNotShuffle.unshuffleList(input, invalidSeed, 10)).to.throw(
        "Shuffling seed must be 32 bytes long"
      );
    });

    it("should throw for invalid number of rounds", () => {
      const input = getInputArray(10);
      const seed = new Uint8Array(32);
      expect(() => swapOrNotShuffle.unshuffleList(input, seed, -1)).to.throw("Rounds must be between 0 and 255");
      expect(() => swapOrNotShuffle.unshuffleList(input, seed, 256)).to.throw("Rounds must be between 0 and 255");
    });

    it("should skip validation for empty and single-element lists (reference validation order)", () => {
      const invalidSeed = Buffer.alloc(31, 0xac);
      expect(Array.from(swapOrNotShuffle.unshuffleList(new Uint32Array([]), invalidSeed, 10))).toEqual([]);
      expect(Array.from(swapOrNotShuffle.unshuffleList(new Uint32Array([7]), invalidSeed, -1))).toEqual([7]);
      // rounds == 0 returns before any validation
      expect(Array.from(swapOrNotShuffle.unshuffleList(new Uint32Array([0, 1, 2]), invalidSeed, 0))).toEqual([0, 1, 2]);
    });

    it("should not mutate the input array", () => {
      const {seed} = randomSeed();
      const input = getInputArray(100);
      swapOrNotShuffle.shuffleList(input, seed, 90);
      expect(Array.from(input)).toEqual(Array.from(getInputArray(100)));
    });

    it("should match spec test results", () => {
      const seed = Buffer.from("4fe91d85d6bc19b20413659c61f3c690a1c4d48be41cab8363a130cebabada97", "hex");
      const expected = [
        99, 71, 51, 5, 78, 61, 12, 17, 30, 3, 59, 47, 6, 9, 1, 41, 18, 37, 55, 43, 20, 31, 38, 79, 29, 69, 70, 54, 53,
        36, 34, 62, 77, 87, 39, 96, 56, 92, 16, 82, 40, 27, 58, 14, 68, 76, 80, 13, 28, 81, 64, 26, 19, 60, 90, 2, 98,
        67, 66, 52, 46, 95, 49, 72, 8, 21, 75, 57, 97, 83, 84, 88, 86, 7, 74, 32, 63, 85, 23, 65, 24, 91, 0, 48, 35, 15,
        44, 25, 22, 73, 93, 45, 4, 33, 89, 94, 10, 42, 11, 50,
      ];

      const result = swapOrNotShuffle.unshuffleList(getInputArray(100), seed, 10);
      expect(Array.from(result)).toEqual(expected);
    });

    const testCases: {count: number; rounds: number}[] = [
      {count: 2, rounds: 10},
      {count: 8, rounds: 10},
      {count: 16, rounds: 10},
      {count: 16, rounds: 100},
      {count: 100, rounds: 90},
      {count: 256, rounds: 192},
      {count: 1000, rounds: 90},
      {count: 16384, rounds: 90},
    ];

    for (const {count, rounds} of testCases) {
      const {seed, id} = randomSeed();
      const input = getInputArray(count);

      it(`sync - ${count} indices, ${rounds} rounds, ${id}`, () => {
        expect(Array.from(swapOrNotShuffle.shuffleList(input, seed, rounds))).toEqual(
          Array.from(reference.shuffleList(input, seed, rounds))
        );
        expect(Array.from(swapOrNotShuffle.unshuffleList(input, seed, rounds))).toEqual(
          Array.from(reference.unshuffleList(input, seed, rounds))
        );
      });

      it(`async - ${count} indices, ${rounds} rounds, ${id}`, async () => {
        expect(Array.from(await swapOrNotShuffle.asyncShuffleList(input, seed, rounds))).toEqual(
          Array.from(await reference.asyncShuffleList(input, seed, rounds))
        );
        expect(Array.from(await swapOrNotShuffle.asyncUnshuffleList(input, seed, rounds))).toEqual(
          Array.from(await reference.asyncUnshuffleList(input, seed, rounds))
        );
      });
    }

    it("async - should reject with reference error message", async () => {
      const input = getInputArray(10);
      await expect(swapOrNotShuffle.asyncUnshuffleList(input, Buffer.alloc(31, 0xac), 10)).rejects.toThrow(
        "Shuffling seed must be 32 bytes long"
      );
      await expect(swapOrNotShuffle.asyncUnshuffleList(input, new Uint8Array(32), 256)).rejects.toThrow(
        "Rounds must be between 0 and 255"
      );
    });
  });

  describe("ComputeShuffledIndex", () => {
    it("should match the reference for every index", () => {
      const {seed, id} = randomSeed();
      const indexCount = 1000;
      const rounds = reference.SHUFFLE_ROUNDS_MAINNET;

      const actual = new swapOrNotShuffle.ComputeShuffledIndex(seed, indexCount, rounds);
      const expected = new reference.ComputeShuffledIndex(seed, indexCount, rounds);
      for (let i = 0; i < indexCount; i++) {
        expect(actual.get(i), `index ${i}, ${id}`).toEqual(expected.get(i));
      }
    });
  });

  describe("committee indices", () => {
    const vc = 1000;
    const activeIndices = getInputArray(vc);
    const effectiveBalanceIncrements = new Uint16Array(vc);
    for (let i = 0; i < vc; i++) {
      effectiveBalanceIncrements[i] = 32 + 32 * (i % 64);
    }
    const MAX_EFFECTIVE_BALANCE = 32_000_000_000;
    const MAX_EFFECTIVE_BALANCE_ELECTRA = 2_048_000_000_000;
    const EFFECTIVE_BALANCE_INCREMENT = 1_000_000_000;
    const SYNC_COMMITTEE_SIZE = 512;
    const rounds = reference.SHUFFLE_ROUNDS_MAINNET;

    it("computeProposerIndex should match the reference", () => {
      for (const byteCount of [reference.ByteCount.One, reference.ByteCount.Two]) {
        const {seed, id} = randomSeed();
        const maxEffectiveBalance =
          byteCount === reference.ByteCount.One ? MAX_EFFECTIVE_BALANCE : MAX_EFFECTIVE_BALANCE_ELECTRA;
        expect(
          swapOrNotShuffle.computeProposerIndex(
            seed,
            activeIndices,
            effectiveBalanceIncrements,
            byteCount,
            maxEffectiveBalance,
            EFFECTIVE_BALANCE_INCREMENT,
            rounds
          ),
          `byteCount ${byteCount}, ${id}`
        ).toEqual(
          reference.computeProposerIndex(
            seed,
            activeIndices,
            effectiveBalanceIncrements,
            byteCount,
            maxEffectiveBalance,
            EFFECTIVE_BALANCE_INCREMENT,
            rounds
          )
        );
      }
    });

    it("computeProposerIndexElectra should match the reference", () => {
      const {seed, id} = randomSeed();
      expect(
        swapOrNotShuffle.computeProposerIndexElectra(
          seed,
          activeIndices,
          effectiveBalanceIncrements,
          MAX_EFFECTIVE_BALANCE_ELECTRA,
          EFFECTIVE_BALANCE_INCREMENT,
          rounds
        ),
        id
      ).toEqual(
        reference.computeProposerIndexElectra(
          seed,
          activeIndices,
          effectiveBalanceIncrements,
          MAX_EFFECTIVE_BALANCE_ELECTRA,
          EFFECTIVE_BALANCE_INCREMENT,
          rounds
        )
      );
    });

    it("computeSyncCommitteeIndices should match the reference", () => {
      for (const byteCount of [reference.ByteCount.One, reference.ByteCount.Two]) {
        const {seed, id} = randomSeed();
        const maxEffectiveBalance =
          byteCount === reference.ByteCount.One ? MAX_EFFECTIVE_BALANCE : MAX_EFFECTIVE_BALANCE_ELECTRA;
        expect(
          Array.from(
            swapOrNotShuffle.computeSyncCommitteeIndices(
              seed,
              activeIndices,
              effectiveBalanceIncrements,
              byteCount,
              SYNC_COMMITTEE_SIZE,
              maxEffectiveBalance,
              EFFECTIVE_BALANCE_INCREMENT,
              rounds
            )
          ),
          `byteCount ${byteCount}, ${id}`
        ).toEqual(
          Array.from(
            reference.computeSyncCommitteeIndices(
              seed,
              activeIndices,
              effectiveBalanceIncrements,
              byteCount,
              SYNC_COMMITTEE_SIZE,
              maxEffectiveBalance,
              EFFECTIVE_BALANCE_INCREMENT,
              rounds
            )
          )
        );
      }
    });

    it("computeSyncCommitteeIndicesElectra should match the reference", () => {
      const {seed, id} = randomSeed();
      expect(
        Array.from(
          swapOrNotShuffle.computeSyncCommitteeIndicesElectra(
            seed,
            activeIndices,
            effectiveBalanceIncrements,
            SYNC_COMMITTEE_SIZE,
            MAX_EFFECTIVE_BALANCE_ELECTRA,
            EFFECTIVE_BALANCE_INCREMENT,
            rounds
          )
        ),
        id
      ).toEqual(
        Array.from(
          reference.computeSyncCommitteeIndicesElectra(
            seed,
            activeIndices,
            effectiveBalanceIncrements,
            SYNC_COMMITTEE_SIZE,
            MAX_EFFECTIVE_BALANCE_ELECTRA,
            EFFECTIVE_BALANCE_INCREMENT,
            rounds
          )
        )
      );
    });
  });
});
