import {ssz} from "@lodestar/types";
import {beforeAll, describe, expect, it} from "vitest";
import bindings from "../src/index.js";
import {pubkeyCache} from "../src/pubkeys.js";
import {createStfState, stfConfig} from "./stfFixture.js";

type BeaconStateView = InstanceType<typeof bindings.BeaconStateView>;
type SyncCommitteeCache = BeaconStateView["currentSyncCommitteeIndexed"];

const epochsPerPeriod = 256;
const slotsPerEpoch = 32;
const nextPeriodEpoch = (Math.floor(stfConfig.FULU_FORK_EPOCH / epochsPerPeriod) + 1) * epochsPerPeriod;
const currentPositions = [0, 2, 511];
const nextPositions = [1, 3, 510];
let state: BeaconStateView;

beforeAll(() => {
  const value = createStfState();
  value.slot = nextPeriodEpoch * slotsPerEpoch - 1;
  for (const position of currentPositions) value.currentSyncCommittee.pubkeys[position] = value.validators[1].pubkey;
  value.nextSyncCommittee.pubkeys.fill(value.validators[2].pubkey);
  for (const position of nextPositions) value.nextSyncCommittee.pubkeys[position] = value.validators[3].pubkey;
  pubkeyCache.ensureCapacity(value.validators.length);
  state = new bindings.StateTransition(stfConfig, new Uint8Array(32)).createFromBytes(
    ssz.fulu.BeaconState.serialize(value)
  );
});

describe("sync committee cache bindings", () => {
  it.each([
    ["current", () => state.currentSyncCommitteeIndexed],
    ["epoch", () => state.getIndexedSyncCommitteeAtEpoch(state.epoch)],
    ["slot", () => state.getIndexedSyncCommittee(state.slot - 1)],
  ] as const)("returns complete repeated-validator positions for %s lookup", (_name, getCache) => {
    expectCache(getCache(), 0, 1, currentPositions);
  });

  it("selects the next period at the epoch boundary and one slot before it for duties", () => {
    expectCache(state.getIndexedSyncCommitteeAtEpoch(nextPeriodEpoch), 2, 3, nextPositions);
    expectCache(state.getIndexedSyncCommittee(state.slot), 2, 3, nextPositions);
    expectCache(state.getIndexedSyncCommittee(state.slot + 1), 2, 3, nextPositions);
  });

  it.each([
    nextPeriodEpoch - epochsPerPeriod - 1,
    nextPeriodEpoch + epochsPerPeriod,
  ])("preserves unavailable committee errors for epoch %s", (epoch) => {
    expect(() => state.getIndexedSyncCommitteeAtEpoch(epoch)).toThrowError(
      expect.objectContaining({code: "NO_SYNC_COMMITTEE"})
    );
    expect(() => state.getIndexedSyncCommittee(epoch * slotsPerEpoch)).toThrowError(
      expect.objectContaining({code: "NO_SYNC_COMMITTEE"})
    );
  });

  it.each([-1, 1.5])("preserves invalid numeric input errors for %s", (value) => {
    expect(() => state.getIndexedSyncCommitteeAtEpoch(value)).toThrowError(
      expect.objectContaining({code: "InvalidUnsignedInteger"})
    );
    expect(() => state.getIndexedSyncCommittee(value)).toThrowError(
      expect.objectContaining({code: "InvalidUnsignedInteger"})
    );
  });
});

function expectCache(cache: SyncCommitteeCache, majority: number, repeated: number, positions: number[]): void {
  expect(cache.validatorIndices).toBeInstanceOf(Uint32Array);
  const expectedIndices = new Uint32Array(512).fill(majority);
  for (const position of positions) expectedIndices[position] = repeated;
  expect(cache.validatorIndices).toEqual(expectedIndices);
  expect(cache.validatorIndexMap).toBeInstanceOf(Map);
  expect(cache.validatorIndexMap.size).toBe(2);
  const majorityPositions = Array.from({length: 512}, (_, position) => position).filter(
    (position) => !positions.includes(position)
  );
  for (const [validatorIndex, expected] of [
    [majority, majorityPositions],
    [repeated, positions],
  ] as const) {
    const actual = cache.validatorIndexMap.get(validatorIndex);
    expect(Array.isArray(actual), `positions for validator ${validatorIndex}`).toBe(true);
    expect(actual, `positions for validator ${validatorIndex}`).toEqual(expected);
  }
  expect(cache.validatorIndexMap.get(15)).toBeUndefined();
}
