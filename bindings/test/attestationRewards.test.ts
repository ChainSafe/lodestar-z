import {createBeaconConfig} from "@lodestar/config";
import {
  computeAttestationsRewards,
  createCachedBeaconState,
  createEmptyEpochCacheImmutableData,
} from "@lodestar/state-transition";
import {ssz} from "@lodestar/types";
import {afterEach, describe, expect, it} from "vitest";
import {SecretKey} from "../src/blst.js";
import bindings from "../src/index.js";
import {pubkeyCache} from "../src/pubkeys.js";

describe("attestation rewards", () => {
  const views: InstanceType<typeof bindings.BeaconStateView>[] = [];

  afterEach(() => {
    for (const view of views) view.release();
    views.length = 0;
  });

  function fixture(fork: "altair" | "bellatrix" | "electra" = "altair", leak = false) {
    const stateType = ssz[fork].BeaconState;
    const value = ssz.electra.BeaconState.defaultValue();
    const validatorCount = 64;
    value.slot = 32 * (leak ? 8 : 2);
    value.validators = Array.from({length: validatorCount}, (_, index) => {
      const secret = new Uint8Array(32);
      secret[31] = index + 1;
      return {
        ...ssz.phase0.Validator.defaultValue(),
        activationEligibilityEpoch: 0,
        activationEpoch: index === 2 ? 1000 : 0,
        effectiveBalance: 32_000_000_000,
        exitEpoch: Infinity,
        pubkey: SecretKey.fromBytes(secret).toPublicKey().toBytes(),
        slashed: index === 1,
        withdrawableEpoch: Infinity,
      };
    });
    value.balances = Array.from({length: validatorCount}, () => 32_000_000_000);
    value.previousEpochParticipation = Array.from({length: validatorCount}, (_, index) => (index % 4 < 2 ? 7 : 0));
    value.currentEpochParticipation = Array.from({length: validatorCount}, () => 0);
    value.inactivityScores = Array.from({length: validatorCount}, () => 1000);
    value.finalizedCheckpoint.epoch = leak ? 0 : 1;
    value.currentSyncCommittee.pubkeys = Array.from(
      {length: value.currentSyncCommittee.pubkeys.length},
      (_, index) => value.validators[index % validatorCount].pubkey
    );
    value.currentSyncCommittee.aggregatePubkey = value.validators[0].pubkey;
    value.nextSyncCommittee = value.currentSyncCommittee;
    const config = createBeaconConfig(
      {
        ALTAIR_FORK_EPOCH: 0,
        BELLATRIX_FORK_EPOCH: fork === "altair" ? Infinity : 0,
        CAPELLA_FORK_EPOCH: fork === "electra" ? 0 : Infinity,
        DENEB_FORK_EPOCH: fork === "electra" ? 0 : Infinity,
        ELECTRA_FORK_EPOCH: fork === "electra" ? 0 : Infinity,
        FULU_FORK_EPOCH: Infinity,
        GLOAS_FORK_EPOCH: Infinity,
      },
      value.genesisValidatorsRoot
    );
    value.fork.currentVersion = config.getForkVersion(value.slot);
    bindings.config.set(config, value.genesisValidatorsRoot);
    pubkeyCache.ensureCapacity(validatorCount);
    pubkeyCache.syncPubkeys(value.validators);
    const reference = createCachedBeaconState(
      stateType.toViewDU(value),
      createEmptyEpochCacheImmutableData(config, value)
    );
    const native = bindings.BeaconStateView.createFromBytes(stateType.serialize(value));
    views.push(native);
    return {config, native, reference, value};
  }

  it.each([false, true])("matches Altair arithmetic and eligibility, inactivity leak=%s", async (leak) => {
    const {config, native, reference} = fixture("altair", leak);
    const root = native.hashTreeRoot();
    const expected = await computeAttestationsRewards(config, reference.epochCtx.pubkey2index, reference);
    const promise = native.computeAttestationsRewards();
    expect(promise).toBeInstanceOf(Promise);
    const rewards = await promise;
    expect(rewards).toEqual(expected);
    expect(rewards.idealRewards).toHaveLength(33);
    expect(rewards.totalRewards.find((reward) => reward.validatorIndex === 2)).toBeUndefined();
    expect(rewards.totalRewards.find((reward) => reward.validatorIndex === 1)?.target).toBeLessThan(0);
    expect(native.hashTreeRoot()).toEqual(root);
  });

  it("uses the Bellatrix inactivity quotient", async () => {
    const {config, native, reference} = fixture("bellatrix");
    const rewards = await native.computeAttestationsRewards([1]);
    const old = await computeAttestationsRewards(config, reference.epochCtx.pubkey2index, reference, [1]);
    const inactivity = -Math.floor((32_000_000_000 * 1000) / (config.INACTIVITY_SCORE_BIAS * 2 ** 24));
    expect(rewards.totalRewards[0]).toEqual({...old.totalRewards[0], inactivity});
    expect(inactivity).not.toBe(old.totalRewards[0].inactivity);
    expect(rewards.idealRewards).toEqual(old.idealRewards);
  });

  it("includes the Electra ideal balance range", async () => {
    const {native} = fixture("electra");
    const rewards = await native.computeAttestationsRewards([0]);
    expect(rewards.idealRewards).toHaveLength(2049);
    expect(rewards.idealRewards[2048].effectiveBalance).toBe(2_048_000_000_000);
    expect(rewards.totalRewards).toHaveLength(1);
  });

  it("sorts and deduplicates selection while accepting mixed-case and unprefixed pubkeys", async () => {
    const {config, native, reference, value} = fixture();
    const hex = Buffer.from(value.validators[0].pubkey).toString("hex");
    const filters = [3, hex.toUpperCase(), `0x${hex}`, 3];
    expect(await native.computeAttestationsRewards(filters)).toEqual(
      await computeAttestationsRewards(config, reference.epochCtx.pubkey2index, reference, filters)
    );
    expect((await native.computeAttestationsRewards([`0x${"00".repeat(48)}`])).totalRewards).toEqual([]);
    expect((await native.computeAttestationsRewards([])).totalRewards).toHaveLength(63);
  });

  it("rejects malformed hexadecimal filters through the Promise", async () => {
    const {native} = fixture();
    await expect(native.computeAttestationsRewards(["0xabc"])).rejects.toThrow(
      "hex string length 3 must be multiple of 2"
    );
    await expect(native.computeAttestationsRewards(["0xzz"])).rejects.toThrow("hex string contains invalid characters");
  });

  it("rejects Phase0 before reading validator filters", async () => {
    const value = ssz.phase0.BeaconState.defaultValue();
    const config = createBeaconConfig({ALTAIR_FORK_EPOCH: Infinity}, value.genesisValidatorsRoot);
    bindings.config.set(config, value.genesisValidatorsRoot);
    const native = bindings.BeaconStateView.createFromBytes(ssz.phase0.BeaconState.serialize(value));
    views.push(native);
    await expect(native.computeAttestationsRewards()).rejects.toThrow(
      "Unsupported fork. Attestations rewards calculation is not available in phase0"
    );
  });

  it("rejects a filter getter releasing the state", async () => {
    const {native} = fixture();
    const ids = [0];
    Object.defineProperty(ids, "0", {
      get() {
        native.release();
        return 0;
      },
    });
    await expect(native.computeAttestationsRewards(ids)).rejects.toThrow("InvalidState");
  });

  it("preserves thrown getter errors", async () => {
    const {native} = fixture();
    const failure = new Error("filter getter failed");
    const ids = [0];
    Object.defineProperty(ids, "0", {
      get() {
        throw failure;
      },
    });
    await expect(native.computeAttestationsRewards(ids)).rejects.toBe(failure);
  });

  it("keeps owned results valid when output setters release the state", async () => {
    const {native} = fixture();
    const descriptor = Object.getOwnPropertyDescriptor(Object.prototype, "head");
    let calls = 0;
    Object.defineProperty(Object.prototype, "head", {
      configurable: true,
      set(head: number) {
        calls++;
        native.release();
        Object.defineProperty(this, "head", {configurable: true, enumerable: true, value: head});
      },
    });
    let result: Awaited<ReturnType<typeof native.computeAttestationsRewards>>;
    try {
      result = await native.computeAttestationsRewards([0]);
    } finally {
      if (descriptor) Object.defineProperty(Object.prototype, "head", descriptor);
      else Reflect.deleteProperty(Object.prototype, "head");
    }
    expect(calls).toBe(34);
    expect(result.totalRewards[0].validatorIndex).toBe(0);
    expect(result.totalRewards[0].head).toBeGreaterThan(0);
  });
});
