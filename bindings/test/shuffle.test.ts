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

    const shuffleInput = Uint32Array.from(input);
    innerShuffleList(shuffleInput, seed, rounds, forwards);
    expect(shuffleInput.length).toEqual(input.length);
    var expected = new Uint32Array([6, 2, 3, 5, 1, 7, 8, 0, 4]);
    expect(shuffleInput).toEqual(expected);

    // shuffle back
    const backwards = true;
    innerShuffleList(shuffleInput, seed, rounds, backwards);
    expected = new Uint32Array([0, 1, 2, 3, 4, 5, 6, 7, 8]);
    expect(shuffleInput).toEqual(expected);
  });

  it("should do nothing with list length <= 1", async () => {
    const input = new Uint32Array([5566]);
    const seed = new Uint8Array(SEED_SIZE).fill(0);
    const rounds = 3;
    const forwards = false;

    const shuffleInputZeroElement = new Uint32Array([]);
    const expectedZeroElement = new Uint32Array([]);
    innerShuffleList(shuffleInputZeroElement, seed, rounds, forwards);
    expect(shuffleInputZeroElement).toEqual(expectedZeroElement);

    const shuffleInputOneElement = Uint32Array.from(input);
    const expectedOneElement = new Uint32Array([5566]);
    innerShuffleList(shuffleInputOneElement, seed, rounds, forwards);
    expect(shuffleInputOneElement).toEqual(expectedOneElement);
  });

  it("should do nothing with round = 0", async () => {
    const input = new Uint32Array([0, 1, 2, 3, 4, 5, 6, 7, 8]);
    const seed = new Uint8Array(SEED_SIZE).fill(0);
    const rounds = 0;
    const forwards = false;
    const expected = new Uint32Array([0, 1, 2, 3, 4, 5, 6, 7, 8]);

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

  it("should fail with invalid rounds > 255", async () => {
    const validInput = new Uint32Array([0, 1, 2, 3, 4, 5, 6, 7, 8]);
    const seed = new Uint8Array(SEED_SIZE).fill(0);
    const invalidRounds = 256;
    const forwards = false;

    expect(() => {
      innerShuffleList(validInput, seed, invalidRounds, forwards);
    }).toThrow("InvalidRoundsSize");
  });

  it("should fail with invalid rounds < 0", async () => {
    const validInput = new Uint32Array([0, 1, 2, 3, 4, 5, 6, 7, 8]);
    const seed = new Uint8Array(SEED_SIZE).fill(0);
    const invalidRounds = -1;
    const forwards = false;

    expect(() => {
      innerShuffleList(validInput, seed, invalidRounds, forwards);
    }).toThrow("InvalidRoundsSize");
  });
});
