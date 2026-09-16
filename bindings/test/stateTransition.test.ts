import {ssz} from "@lodestar/types";
import {beforeAll, describe, expect, it} from "vitest";
import bindings from "../src/index.js";
import {createStfState, stfConfig} from "./stfFixture.js";

describe("serialized state transition", () => {
  let state: InstanceType<typeof bindings.BeaconStateView>;

  beforeAll(() => {
    bindings.config.set(stfConfig, new Uint8Array(32));
    bindings.pubkeys.ensureCapacity(16);
    state = bindings.BeaconStateView.createFromBytes(ssz.fulu.BeaconState.serialize(createStfState()));
  });

  it.each([false, true])("decodes a block with isBlinded=%s before checking its parent", (isBlinded) => {
    const type = isBlinded ? ssz.fulu.SignedBlindedBeaconBlock : ssz.fulu.SignedBeaconBlock;
    const block = type.defaultValue();
    block.message.slot = state.slot + 1;
    block.message.proposerIndex = state.getBeaconProposer(block.message.slot);
    const before = state.hashTreeRoot();

    expect(() =>
      state.stateTransition(type.serialize(block), isBlinded, {
        verifyProposer: false,
        verifySignatures: false,
        verifyStateRoot: false,
      })
    ).toThrow("BlockParentRootMismatch");
    expect(state.hashTreeRoot()).toEqual(before);
  });

  it("exports the fork sequence used by Lodestar", () => {
    expect(state.forkSeq).toBe(6);
    expect(state.forkName).toBe("fulu");
  });

  it("preserves execution header bigint fields in values and SSZ roundtrips", () => {
    const value = createStfState();
    value.latestExecutionPayloadHeader.baseFeePerGas = 1n;
    value.latestExecutionPayloadHeader.blobGasUsed = 2n;
    value.latestExecutionPayloadHeader.excessBlobGas = 3n;
    value.pendingPartialWithdrawals = [{amount: 1n, validatorIndex: 0, withdrawableEpoch: Infinity}];
    const bytes = ssz.fulu.BeaconState.serialize(value);
    const native = bindings.BeaconStateView.createFromBytes(bytes);
    expect(native.latestExecutionPayloadHeader).toEqual(value.latestExecutionPayloadHeader);
    expect(ssz.fulu.BeaconState.serialize(native.toValue())).toEqual(bytes);
  }, 30_000);

  it("returns expected withdrawal amounts as bigint", () => {
    const value = createStfState();
    value.validators[0].withdrawalCredentials[0] = 1;
    value.balances[0] = 33_000_000_000;
    const native = bindings.BeaconStateView.createFromBytes(ssz.fulu.BeaconState.serialize(value));
    expect(native.getExpectedWithdrawals().expectedWithdrawals[0].amount).toBe(1_000_000_000n);
  });

  describe.each([
    {SECONDS_PER_SLOT: undefined, SLOT_DURATION_MS: 6000, name: "milliseconds only"},
    {SECONDS_PER_SLOT: 12, SLOT_DURATION_MS: 6000, name: "milliseconds with stale legacy seconds"},
    {SECONDS_PER_SLOT: 6, SLOT_DURATION_MS: undefined, name: "legacy seconds only"},
  ])("$name", ({SECONDS_PER_SLOT, SLOT_DURATION_MS}) => {
    it.each([false, true])("transitions isBlinded=%s with a non-default slot duration", (isBlinded) => {
      const chainConfig = {...stfConfig, SECONDS_PER_SLOT, SLOT_DURATION_MS};
      const value = createStfState();
      value.latestExecutionPayloadHeader.blockHash.fill(1);
      const native = new bindings.StateTransition(chainConfig, new Uint8Array(32)).createFromBytes(
        ssz.fulu.BeaconState.serialize(value)
      );
      const slot = native.slot + 1;
      const advanced = native.processSlots(slot);
      const block = ssz.fulu.SignedBeaconBlock.defaultValue();
      block.message.slot = slot;
      block.message.proposerIndex = advanced.getBeaconProposer(slot);
      block.message.parentRoot = ssz.phase0.BeaconBlockHeader.hashTreeRoot(advanced.latestBlockHeader);
      block.message.body.executionPayload.parentHash.fill(1);
      block.message.body.executionPayload.blockHash.fill(2);
      block.message.body.executionPayload.timestamp = slot * 6;
      const payload = block.message.body.executionPayload;
      const blinded = {
        ...block,
        message: {
          ...block.message,
          body: {
            ...block.message.body,
            executionPayloadHeader: {
              ...payload,
              transactionsRoot: ssz.bellatrix.Transactions.hashTreeRoot(payload.transactions),
              withdrawalsRoot: ssz.capella.Withdrawals.hashTreeRoot(payload.withdrawals),
            },
          },
        },
      };
      const bytes = isBlinded
        ? ssz.fulu.SignedBlindedBeaconBlock.serialize(blinded)
        : ssz.fulu.SignedBeaconBlock.serialize(block);
      const post = native.stateTransition(bytes, isBlinded, {
        dataAvailabilityStatus: "Available",
        executionPayloadStatus: "valid",
        verifyProposer: false,
        verifySignatures: false,
        verifyStateRoot: false,
      });
      expect(post.slot).toBe(slot);
      expect(post.latestExecutionPayloadHeader.timestamp).toBe(slot * 6);
      expect(native.slot).toBe(value.slot);
    });
  });
});
