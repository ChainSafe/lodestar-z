import {config} from "@lodestar/config/default";
import {EpochCache, computeStartSlotAtEpoch, createEmptyEpochCacheImmutableData} from "@lodestar/state-transition";
import {ssz} from "@lodestar/types";
import {expect, it} from "vitest";
import {SecretKey} from "../src/blst.js";
import bindings from "../src/index.js";

it("Electra next proposer getters match the TypeScript lazy cache", () => {
  const validatorCount = 64;
  const slotsPerEpoch = computeStartSlotAtEpoch(1);
  const value = ssz.electra.BeaconState.defaultValue();
  value.slot = config.ELECTRA_FORK_EPOCH * slotsPerEpoch;
  value.validators = Array.from({length: validatorCount}, (_, index) => ({
    ...ssz.phase0.Validator.defaultValue(),
    effectiveBalance: 32_000_000_000,
    exitEpoch: Infinity,
    pubkey: SecretKey.fromKeygen(new Uint8Array(32).fill(index + 1))
      .toPublicKey()
      .toBytes(),
    withdrawableEpoch: Infinity,
  }));
  value.balances = Array.from({length: validatorCount}, () => 32_000_000_000);
  value.previousEpochParticipation = Array.from({length: validatorCount}, () => 0);
  value.currentEpochParticipation = Array.from({length: validatorCount}, () => 0);
  value.inactivityScores = Array.from({length: validatorCount}, () => 0);
  value.currentSyncCommittee = {
    aggregatePubkey: value.validators[0].pubkey,
    pubkeys: Array.from(
      {length: value.currentSyncCommittee.pubkeys.length},
      (_, index) => value.validators[index % validatorCount].pubkey
    ),
  };
  value.nextSyncCommittee = value.currentSyncCommittee;

  const tsState = ssz.electra.BeaconState.toViewDU(value);
  const tsCache = EpochCache.createFromState(tsState, createEmptyEpochCacheImmutableData(config, tsState), {
    skipSyncCommitteeCache: true,
    skipSyncPubkeys: true,
  });
  const expected = tsCache.getBeaconProposersNextEpoch();
  bindings.pubkeys.ensureCapacity(validatorCount);
  const bytes = ssz.electra.BeaconState.serialize(value);
  const state = bindings.BeaconStateView.createFromBytes(bytes);
  expect(state.nextProposers).toEqual(expected);

  const slotFirst = bindings.BeaconStateView.createFromBytes(bytes);
  const nextEpochSlot = value.slot + slotsPerEpoch;
  expect(slotFirst.getBeaconProposer(nextEpochSlot)).toBe(expected[0]);
  expect(slotFirst.nextProposers).toEqual(expected);
});
