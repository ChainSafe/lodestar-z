import {describe, expect, it} from "vitest";

const bindings = await import("../src/index.ts");
const innerShuffleList = bindings.default.shuffle.innerShuffleList;
const SEED_SIZE = 32;

describe("innerShuffleList", () => {
  it("should shuffle forwards and backwards correctly", async () => {
    const input = new Uint32Array([0, 1, 2, 3, 4, 5, 6, 7, 8]);
    const seed = new Uint8Array(SEED_SIZE).fill(0);
    const rounds = 32;
    const forwards = false;

    innerShuffleList(input, seed, rounds, forwards);
    expect(input.length).toEqual(input.length);
    var expected = new Uint32Array([6, 2, 3, 5, 1, 7, 8, 0, 4]);
    expect(input).toEqual(expected);

    // shuffle back
    const backwards = true;
    innerShuffleList(input, seed, rounds, backwards);
    expected = new Uint32Array([0, 1, 2, 3, 4, 5, 6, 7, 8]);
    expect(input).toEqual(expected);
  });

  it("should do nothing with list length <= 1", async () => {
    const inputs = [new Uint32Array([]), new Uint32Array([5566])];
    const expected = [new Uint32Array([]), new Uint32Array([5566])];
    const seed = new Uint8Array(SEED_SIZE).fill(0);
    const rounds = 3;
    const forwards = false;

    for (let i = 0; i < inputs.length; i++) {
      innerShuffleList(inputs[i], seed, rounds, forwards);
      expect(inputs[i]).toEqual(expected[i]);
    }
  });

  it("should do nothing with round = 0", async () => {
    const input = new Uint32Array([0, 1, 2, 3, 4, 5, 6, 7, 8]);
    const expected = new Uint32Array([0, 1, 2, 3, 4, 5, 6, 7, 8]);
    const seed = new Uint8Array(SEED_SIZE).fill(0);
    const rounds = 0;
    const forwards = false;

    innerShuffleList(input, seed, rounds, forwards);
    expect(input).toEqual(expected);
  });

  it("should fail with invalid input type", async () => {
    const invalidInput = [0, 1, 2, 3, 4, 5, 6, 7, 8];
    const seed = new Uint8Array(SEED_SIZE).fill(0);
    const rounds = 32;
    const forwards = false;
    expect(() => {
      innerShuffleList(invalidInput as any, seed, rounds, forwards);
    }).toThrow("Invalid argument");
  });

  it("should fail with invalid rounds", async () => {
    const validInput = new Uint32Array([0, 1, 2, 3, 4, 5, 6, 7, 8]);
    const seed = new Uint8Array(SEED_SIZE).fill(0);
    const invalidNumRounds = [-1, 256];
    const forwards = false;

    for (let r of invalidNumRounds) {
      expect(() => {
        innerShuffleList(validInput, seed, r, forwards);
      }).toThrow("InvalidRoundsSize");
    }
  });
});
