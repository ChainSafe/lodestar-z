import {ssz} from "@lodestar/types";
import {describe, expect, it} from "vitest";
import {SecretKey} from "../src/blst.js";
import {createPubkeyCache} from "../src/pubkeys.js";

function publicKey(seed: number): Uint8Array {
  const ikm = new Uint8Array(32);
  ikm[0] = seed;
  return SecretKey.fromKeygen(ikm).toPublicKey().toBytes();
}

function stateBytes(pubkey: Uint8Array): Uint8Array {
  const state = ssz.phase0.BeaconState.defaultValue();
  state.validators = [
    {
      activationEligibilityEpoch: 0,
      activationEpoch: 0,
      effectiveBalance: 32_000_000_000,
      exitEpoch: Number.MAX_SAFE_INTEGER,
      pubkey,
      slashed: false,
      withdrawableEpoch: Number.MAX_SAFE_INTEGER,
      withdrawalCredentials: new Uint8Array(32),
    },
  ];
  state.balances = [32_000_000_000];
  return ssz.phase0.BeaconState.serialize(state);
}

describe("pubkey registry isolation", () => {
  it("keeps the same validator index isolated between registries", () => {
    const registryA = createPubkeyCache();
    const registryB = createPubkeyCache();
    const pubkeyA = publicKey(1);
    const pubkeyB = publicKey(2);

    registryA.createBeaconStateView(stateBytes(pubkeyA));
    registryB.createBeaconStateView(stateBytes(pubkeyB));

    expect(registryA.get(0)?.toBytes()).toEqual(pubkeyA);
    expect(registryB.get(0)?.toBytes()).toEqual(pubkeyB);
    expect(registryA.getIndex(pubkeyB)).toBeNull();
    expect(registryB.getIndex(pubkeyA)).toBeNull();
  });
});
