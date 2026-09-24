import {createBeaconConfig} from "@lodestar/config";
import {createCachedBeaconState, createEmptyEpochCacheImmutableData} from "@lodestar/state-transition";
import {ssz} from "@lodestar/types";
import {afterEach, beforeAll, describe, expect, it} from "vitest";
import {SecretKey} from "../src/blst.js";
import bindings from "../src/index.js";
import {pubkeyCache} from "../src/pubkeys.js";

describe("sync committee rewards", () => {
  const validatorCount = 64;
  const value = ssz.bellatrix.BeaconState.defaultValue();
  const views: InstanceType<typeof bindings.BeaconStateView>[] = [];
  let participantReward: number;
  let bytes: Uint8Array;
  let appearances: number;

  beforeAll(() => {
    value.slot = 32;
    value.validators = Array.from({length: validatorCount}, (_, index) => {
      const secret = new Uint8Array(32);
      secret[31] = index + 1;
      return {
        ...ssz.phase0.Validator.defaultValue(),
        activationEligibilityEpoch: 0,
        activationEpoch: 0,
        effectiveBalance: 32_000_000_000,
        exitEpoch: Infinity,
        pubkey: SecretKey.fromBytes(secret).toPublicKey().toBytes(),
        withdrawableEpoch: Infinity,
      };
    });
    value.balances = Array.from({length: validatorCount}, () => 32_000_000_000);
    value.previousEpochParticipation = Array.from({length: validatorCount}, () => 0);
    value.currentEpochParticipation = Array.from({length: validatorCount}, () => 0);
    value.inactivityScores = Array.from({length: validatorCount}, () => 0);
    const order = [2, 0, 1, ...Array.from({length: validatorCount - 3}, (_, index) => index + 3)];
    const committeeSize = value.currentSyncCommittee.pubkeys.length;
    appearances = committeeSize / validatorCount;
    value.currentSyncCommittee.pubkeys = Array.from(
      {length: committeeSize},
      (_, index) => value.validators[order[index % validatorCount]].pubkey
    );
    value.currentSyncCommittee.aggregatePubkey = value.validators[0].pubkey;
    value.nextSyncCommittee = value.currentSyncCommittee;
    const config = createBeaconConfig(
      {
        ALTAIR_FORK_EPOCH: 1,
        BELLATRIX_FORK_EPOCH: 1,
        CAPELLA_FORK_EPOCH: Infinity,
        DENEB_FORK_EPOCH: Infinity,
        ELECTRA_FORK_EPOCH: Infinity,
        FULU_FORK_EPOCH: Infinity,
        GLOAS_FORK_EPOCH: Infinity,
      },
      value.genesisValidatorsRoot
    );
    value.fork.currentVersion = config.BELLATRIX_FORK_VERSION;
    bindings.config.set(config, value.genesisValidatorsRoot);
    pubkeyCache.ensureCapacity(validatorCount);
    pubkeyCache.syncPubkeys(value.validators);
    const reference = createCachedBeaconState(
      ssz.bellatrix.BeaconState.toViewDU(value),
      createEmptyEpochCacheImmutableData(config, value)
    );
    participantReward = reference.epochCtx.syncParticipantReward;
    bytes = ssz.bellatrix.BeaconState.serialize(value);
  });

  afterEach(() => {
    for (const view of views) view.release();
    views.length = 0;
  });

  function state() {
    const view = bindings.BeaconStateView.createFromBytes(bytes);
    views.push(view);
    return view;
  }

  function block(blinded = false) {
    const blockValue = blinded
      ? ssz.bellatrix.BlindedBeaconBlock.defaultValue()
      : ssz.bellatrix.BeaconBlock.defaultValue();
    blockValue.slot = value.slot;
    const bits = blockValue.body.syncAggregate.syncCommitteeBits;
    for (let round = 0; round < appearances; round++) {
      bits.set(round * validatorCount + 1, true);
      if (round < appearances / 2) bits.set(round * validatorCount, true);
    }
    return blockValue;
  }

  it.each([false, true])("returns signed deltas in first-seen order, blinded=%s", async (blinded) => {
    const view = state();
    const root = view.hashTreeRoot();
    const promise = view.computeSyncCommitteeRewards(block(blinded));
    expect(promise).toBeInstanceOf(Promise);
    const rewards = await promise;
    expect(rewards).toEqual([
      {reward: 0, validatorIndex: 2},
      {reward: appearances * participantReward, validatorIndex: 0},
      {reward: -appearances * participantReward, validatorIndex: 1},
      ...Array.from({length: validatorCount - 3}, (_, index) => ({
        reward: -appearances * participantReward,
        validatorIndex: index + 3,
      })),
    ]);
    expect(view.hashTreeRoot()).toEqual(root);
  });

  it("filters canonical pubkeys and numeric indices without changing order or duplicating rows", async () => {
    const view = state();
    const pubkey = `0x${Buffer.from(value.validators[0].pubkey).toString("hex")}`;
    expect(await view.computeSyncCommitteeRewards(block(), [0, 2, pubkey, 0])).toEqual([
      {reward: 0, validatorIndex: 2},
      {reward: appearances * participantReward, validatorIndex: 0},
    ]);
    expect(await view.computeSyncCommitteeRewards(block(), ["0", pubkey.toUpperCase(), "unknown", 99999])).toEqual([]);
    expect(await view.computeSyncCommitteeRewards(block(), [])).toHaveLength(validatorCount);
  });

  it("rejects a Phase0 block before reading absent sync aggregate fields", async () => {
    await expect(state().computeSyncCommitteeRewards(ssz.phase0.BeaconBlock.defaultValue())).rejects.toThrow(
      "Cannot get sync rewards as phase0 block does not have sync committee"
    );
  });

  it("rejects malformed bits through a Promise", async () => {
    const input = block();
    const malformed = {
      body: {...input.body, syncAggregate: {syncCommitteeBits: {bitLen: 512, uint8Array: new Uint8Array(1)}}},
      slot: input.slot,
    };
    const promise = state().computeSyncCommitteeRewards(malformed);
    expect(promise).toBeInstanceOf(Promise);
    await expect(promise).rejects.toThrow("InvalidByteArrayLength");
  });

  it("preserves a throwing getter as the Promise rejection", async () => {
    const failure = new Error("input getter failed");
    const input = {
      body: block().body,
      get slot(): number {
        throw failure;
      },
    };
    const promise = state().computeSyncCommitteeRewards(input);
    expect(promise).toBeInstanceOf(Promise);
    await expect(promise).rejects.toBe(failure);
  });

  it("rejects release during an input getter without accessing freed state", async () => {
    const view = state();
    const input = {
      body: block().body,
      get slot() {
        view.release();
        return value.slot;
      },
    };
    await expect(view.computeSyncCommitteeRewards(input)).rejects.toThrow("InvalidState");
  });
  it("keeps native results valid when an output setter releases the state", async () => {
    const view = state();
    const descriptor = Object.getOwnPropertyDescriptor(Object.prototype, "reward");
    let calls = 0;
    Object.defineProperty(Object.prototype, "reward", {
      configurable: true,
      set(reward: number) {
        calls++;
        view.release();
        Object.defineProperty(this, "reward", {configurable: true, enumerable: true, value: reward});
      },
    });
    let result: Awaited<ReturnType<typeof view.computeSyncCommitteeRewards>>;
    try {
      result = await view.computeSyncCommitteeRewards(block());
    } finally {
      if (descriptor) Object.defineProperty(Object.prototype, "reward", descriptor);
      else Reflect.deleteProperty(Object.prototype, "reward");
    }
    expect(calls).toBe(validatorCount);
    expect(result[1]).toEqual({reward: appearances * participantReward, validatorIndex: 0});
  });
});
