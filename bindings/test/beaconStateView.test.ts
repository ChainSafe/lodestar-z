import {config} from "@lodestar/config/default";
import * as era from "@lodestar/era";
import {computeEpochAtSlot} from "@lodestar/state-transition";
import {ssz} from "@lodestar/types";
import {beforeAll, describe, expect, it} from "vitest";
import bindings from "../src/index.ts";
import {getFirstEraFilePath} from "./eraFiles.ts";

describe("BeaconStateView", () => {
  let state: InstanceType<typeof bindings.BeaconStateView>;
  let stateBytes: Uint8Array;
  // Expected values extracted from lodestar's tree view.
  // The full tree (~3-4GB for mainnet) is freed before creating the native state
  // so the two large allocations never coexist in memory (avoids OOM on CI).
  let expected: {
    slot: number;
    genesisTime: number;
    genesisValidatorsRoot: Uint8Array;
    validatorCount: number;
    fork: {previousVersion: Uint8Array; currentVersion: Uint8Array; epoch: number};
    eth1Data: {depositRoot: Uint8Array; depositCount: number; blockHash: Uint8Array};
    latestBlockHeader: {
      slot: number;
      proposerIndex: number;
      parentRoot: Uint8Array;
      stateRoot: Uint8Array;
      bodyRoot: Uint8Array;
    };
    previousJustifiedCheckpoint: {epoch: number; root: Uint8Array};
    currentJustifiedCheckpoint: {epoch: number; root: Uint8Array};
    finalizedCheckpoint: {epoch: number; root: Uint8Array};
    currentSyncCommittee: {aggregatePubkey: Uint8Array};
    nextSyncCommittee: {aggregatePubkey: Uint8Array};
    latestExecutionPayloadHeader: {
      blockNumber: number;
      blockHash: Uint8Array;
      parentHash: Uint8Array;
      stateRoot: Uint8Array;
      timestamp: number;
      gasLimit: number;
      gasUsed: number;
    };
    balance0: number;
    balance100: number;
    validator0: {
      pubkey: Uint8Array;
      withdrawalCredentials: Uint8Array;
      effectiveBalance: number;
      slashed: boolean;
      activationEligibilityEpoch: number;
      activationEpoch: number;
      exitEpoch: number;
      withdrawableEpoch: number;
    };
  };

  beforeAll(async () => {
    // Ensure capacity for the state
    bindings.pool.ensureCapacity(10_000_000);
    bindings.pubkeys.ensureCapacity(2_000_000);

    // if pubkey index file exists, load it
    try {
      bindings.pubkeys.load("./mainnet.pkix");
    } catch (_e) {
      // ignore error
    }

    // Load era file
    const reader = await era.era.EraReader.open(config, getFirstEraFilePath());
    stateBytes = await reader.readSerializedState();

    // Phase 1: Build lodestar tree view and extract reference values.
    // Scoped so lodestarState is eligible for GC before we allocate the native state.
    {
      const lodestarState = ssz.fulu.BeaconState.deserializeToView(stateBytes);
      const v0 = lodestarState.validators.get(0);
      expected = {
        balance0: lodestarState.balances.get(0),
        balance100: lodestarState.balances.get(100),
        currentJustifiedCheckpoint: {
          epoch: lodestarState.currentJustifiedCheckpoint.epoch,
          root: Uint8Array.from(lodestarState.currentJustifiedCheckpoint.root),
        },
        currentSyncCommittee: {
          aggregatePubkey: Uint8Array.from(lodestarState.currentSyncCommittee.aggregatePubkey),
        },
        eth1Data: {
          blockHash: Uint8Array.from(lodestarState.eth1Data.blockHash),
          depositCount: lodestarState.eth1Data.depositCount,
          depositRoot: Uint8Array.from(lodestarState.eth1Data.depositRoot),
        },
        finalizedCheckpoint: {
          epoch: lodestarState.finalizedCheckpoint.epoch,
          root: Uint8Array.from(lodestarState.finalizedCheckpoint.root),
        },
        fork: {
          currentVersion: Uint8Array.from(lodestarState.fork.currentVersion),
          epoch: lodestarState.fork.epoch,
          previousVersion: Uint8Array.from(lodestarState.fork.previousVersion),
        },
        genesisTime: lodestarState.genesisTime,
        genesisValidatorsRoot: Uint8Array.from(lodestarState.genesisValidatorsRoot),
        latestBlockHeader: {
          bodyRoot: Uint8Array.from(lodestarState.latestBlockHeader.bodyRoot),
          parentRoot: Uint8Array.from(lodestarState.latestBlockHeader.parentRoot),
          proposerIndex: lodestarState.latestBlockHeader.proposerIndex,
          slot: lodestarState.latestBlockHeader.slot,
          stateRoot: Uint8Array.from(lodestarState.latestBlockHeader.stateRoot),
        },
        latestExecutionPayloadHeader: {
          blockHash: Uint8Array.from(lodestarState.latestExecutionPayloadHeader.blockHash),
          blockNumber: lodestarState.latestExecutionPayloadHeader.blockNumber,
          gasLimit: lodestarState.latestExecutionPayloadHeader.gasLimit,
          gasUsed: lodestarState.latestExecutionPayloadHeader.gasUsed,
          parentHash: Uint8Array.from(lodestarState.latestExecutionPayloadHeader.parentHash),
          stateRoot: Uint8Array.from(lodestarState.latestExecutionPayloadHeader.stateRoot),
          timestamp: lodestarState.latestExecutionPayloadHeader.timestamp,
        },
        nextSyncCommittee: {
          aggregatePubkey: Uint8Array.from(lodestarState.nextSyncCommittee.aggregatePubkey),
        },
        previousJustifiedCheckpoint: {
          epoch: lodestarState.previousJustifiedCheckpoint.epoch,
          root: Uint8Array.from(lodestarState.previousJustifiedCheckpoint.root),
        },
        slot: lodestarState.slot,
        validator0: {
          activationEligibilityEpoch: v0.activationEligibilityEpoch,
          activationEpoch: v0.activationEpoch,
          effectiveBalance: v0.effectiveBalance,
          exitEpoch: v0.exitEpoch,
          pubkey: Uint8Array.from(v0.pubkey),
          slashed: v0.slashed,
          withdrawableEpoch: v0.withdrawableEpoch,
          withdrawalCredentials: Uint8Array.from(v0.withdrawalCredentials),
        },
        validatorCount: lodestarState.validators.length,
      };
    }
    // lodestarState is now out of scope — reclaim the tree before allocating the native state
    global.gc?.();

    // Phase 2: Create the native state (only after lodestar tree is freed)
    state = bindings.BeaconStateView.createFromBytes(stateBytes);
  }, 120_000); // 2 minute timeout for loading era file

  describe("basic properties", () => {
    it("slot should match lodestar", () => {
      expect(state.slot).toBe(expected.slot);
    });

    it("epoch should be computed correctly from slot", () => {
      const expectedEpoch = computeEpochAtSlot(state.slot);
      expect(state.epoch).toBe(expectedEpoch);
    });

    it("genesisTime should match lodestar", () => {
      expect(state.genesisTime).toBe(expected.genesisTime);
    });

    it("genesisValidatorsRoot should match lodestar", () => {
      expect(state.genesisValidatorsRoot).toEqual(expected.genesisValidatorsRoot);
    });

    it("validatorCount should match lodestar", () => {
      expect(state.validatorCount).toBe(expected.validatorCount);
    });
  });

  describe("fork", () => {
    it("fork.previousVersion should match lodestar", () => {
      expect(state.fork.previousVersion).toEqual(expected.fork.previousVersion);
    });

    it("fork.currentVersion should match lodestar", () => {
      expect(state.fork.currentVersion).toEqual(expected.fork.currentVersion);
    });

    it("fork.epoch should match lodestar", () => {
      expect(state.fork.epoch).toBe(expected.fork.epoch);
    });
  });

  describe("eth1Data", () => {
    it("eth1Data.depositRoot should match lodestar", () => {
      expect(state.eth1Data.depositRoot).toEqual(expected.eth1Data.depositRoot);
    });

    it("eth1Data.depositCount should match lodestar", () => {
      expect(state.eth1Data.depositCount).toBe(expected.eth1Data.depositCount);
    });

    it("eth1Data.blockHash should match lodestar", () => {
      expect(state.eth1Data.blockHash).toEqual(expected.eth1Data.blockHash);
    });
  });

  describe("latestBlockHeader", () => {
    it("latestBlockHeader.slot should match lodestar", () => {
      expect(state.latestBlockHeader.slot).toBe(expected.latestBlockHeader.slot);
    });

    it("latestBlockHeader.proposerIndex should match lodestar", () => {
      expect(state.latestBlockHeader.proposerIndex).toBe(expected.latestBlockHeader.proposerIndex);
    });

    it("latestBlockHeader.parentRoot should match lodestar", () => {
      expect(state.latestBlockHeader.parentRoot).toEqual(expected.latestBlockHeader.parentRoot);
    });

    it("latestBlockHeader.stateRoot should match lodestar", () => {
      expect(state.latestBlockHeader.stateRoot).toEqual(expected.latestBlockHeader.stateRoot);
    });

    it("latestBlockHeader.bodyRoot should match lodestar", () => {
      expect(state.latestBlockHeader.bodyRoot).toEqual(expected.latestBlockHeader.bodyRoot);
    });
  });

  describe("checkpoints", () => {
    it("previousJustifiedCheckpoint should match lodestar", () => {
      expect(state.previousJustifiedCheckpoint.epoch).toBe(expected.previousJustifiedCheckpoint.epoch);
      expect(state.previousJustifiedCheckpoint.root).toEqual(expected.previousJustifiedCheckpoint.root);
    });

    it("currentJustifiedCheckpoint should match lodestar", () => {
      expect(state.currentJustifiedCheckpoint.epoch).toBe(expected.currentJustifiedCheckpoint.epoch);
      expect(state.currentJustifiedCheckpoint.root).toEqual(expected.currentJustifiedCheckpoint.root);
    });

    it("finalizedCheckpoint should match lodestar", () => {
      expect(state.finalizedCheckpoint.epoch).toBe(expected.finalizedCheckpoint.epoch);
      expect(state.finalizedCheckpoint.root).toEqual(expected.finalizedCheckpoint.root);
    });
  });

  describe("sync committees (altair+)", () => {
    it("currentSyncCommittee.aggregatePubkey should match lodestar", () => {
      expect(state.currentSyncCommittee.aggregatePubkey).toEqual(expected.currentSyncCommittee.aggregatePubkey);
    });

    it("nextSyncCommittee.aggregatePubkey should match lodestar", () => {
      expect(state.nextSyncCommittee.aggregatePubkey).toEqual(expected.nextSyncCommittee.aggregatePubkey);
    });
  });

  describe("execution payload header (bellatrix+)", () => {
    it("latestExecutionPayloadHeader.blockNumber should match lodestar", () => {
      expect(state.latestExecutionPayloadHeader.blockNumber).toBe(expected.latestExecutionPayloadHeader.blockNumber);
    });

    it("latestExecutionPayloadHeader.blockHash should match lodestar", () => {
      expect(state.latestExecutionPayloadHeader.blockHash).toEqual(expected.latestExecutionPayloadHeader.blockHash);
    });

    it("latestExecutionPayloadHeader.parentHash should match lodestar", () => {
      expect(state.latestExecutionPayloadHeader.parentHash).toEqual(expected.latestExecutionPayloadHeader.parentHash);
    });

    it("latestExecutionPayloadHeader.stateRoot should match lodestar", () => {
      expect(state.latestExecutionPayloadHeader.stateRoot).toEqual(expected.latestExecutionPayloadHeader.stateRoot);
    });

    it("latestExecutionPayloadHeader.timestamp should match lodestar", () => {
      expect(state.latestExecutionPayloadHeader.timestamp).toBe(expected.latestExecutionPayloadHeader.timestamp);
    });

    it("latestExecutionPayloadHeader.gasLimit should match lodestar", () => {
      expect(state.latestExecutionPayloadHeader.gasLimit).toBe(expected.latestExecutionPayloadHeader.gasLimit);
    });

    it("latestExecutionPayloadHeader.gasUsed should match lodestar", () => {
      expect(state.latestExecutionPayloadHeader.gasUsed).toBe(expected.latestExecutionPayloadHeader.gasUsed);
    });

    it("isMergeTransitionComplete should be true for fulu state", () => {
      expect(state.isMergeTransitionComplete).toBe(true);
    });

    it("isExecutionStateType should be true for fulu state", () => {
      expect(state.isExecutionStateType).toBe(true);
    });
  });

  describe("validators and balances", () => {
    it("getBalance(0) should return first validator balance", () => {
      expect(state.getBalance(0)).toBe(BigInt(expected.balance0));
    });

    it("getBalance(100) should return validator 100 balance", () => {
      expect(state.getBalance(100)).toBe(BigInt(expected.balance100));
    });

    it("getValidator(0) should return first validator data", () => {
      const validator = state.getValidator(0);

      expect(validator.pubkey).toEqual(expected.validator0.pubkey);
      expect(validator.withdrawalCredentials).toEqual(expected.validator0.withdrawalCredentials);
      expect(validator.effectiveBalance).toBe(expected.validator0.effectiveBalance);
      expect(validator.slashed).toBe(expected.validator0.slashed);
      expect(validator.activationEligibilityEpoch).toBe(expected.validator0.activationEligibilityEpoch);
      expect(validator.activationEpoch).toBe(expected.validator0.activationEpoch);
      expect(validator.exitEpoch).toBe(expected.validator0.exitEpoch);
      expect(validator.withdrawableEpoch).toBe(expected.validator0.withdrawableEpoch);
    });

    it("getValidatorStatus should return a valid status string", () => {
      const status = state.getValidatorStatus(0);
      const validStatuses = [
        "pending_initialized",
        "pending_queued",
        "active_ongoing",
        "active_exiting",
        "active_slashed",
        "exited_unslashed",
        "exited_slashed",
        "withdrawal_possible",
        "withdrawal_done",
      ];
      expect(validStatuses).toContain(status);
    });

    it("activeValidatorCount should be positive", () => {
      expect(state.activeValidatorCount).toBeGreaterThan(0);
    });

    it("effectiveBalanceIncrements should have correct length", () => {
      expect(state.effectiveBalanceIncrements.length).toBe(state.validatorCount);
    });
  });

  describe("participation (altair+)", () => {
    it("previousEpochParticipation should have correct length", () => {
      expect(state.previousEpochParticipation.length).toBe(state.validatorCount);
    });

    it("currentEpochParticipation should have correct length", () => {
      expect(state.currentEpochParticipation.length).toBe(state.validatorCount);
    });
  });

  describe("electra+ fields", () => {
    it("pendingDepositsCount should be a non-negative number", () => {
      expect(state.pendingDepositsCount).toBeGreaterThanOrEqual(0);
    });

    it("pendingPartialWithdrawalsCount should be a non-negative number", () => {
      expect(state.pendingPartialWithdrawalsCount).toBeGreaterThanOrEqual(0);
    });

    it("pendingConsolidationsCount should be a non-negative number", () => {
      expect(state.pendingConsolidationsCount).toBeGreaterThanOrEqual(0);
    });

    it("historicalSummaries should be an array", () => {
      expect(Array.isArray(state.historicalSummaries)).toBe(true);
    });
  });

  describe("fulu+ fields", () => {
    it("proposerLookahead should be a Uint32Array", () => {
      expect(state.proposerLookahead).toBeInstanceOf(Uint32Array);
    });
  });

  describe("block and state roots", () => {
    it("getBlockRoot should return 32 bytes", () => {
      const blockRoot = state.getBlockRoot(state.slot - 1);
      expect(blockRoot.length).toBe(32);
    });

    it("getRandaoMix should return 32 bytes", () => {
      const randaoMix = state.getRandaoMix(state.epoch);
      expect(randaoMix.length).toBe(32);
    });
  });

  describe("proposers and shuffling", () => {
    it("currentProposers should be an array of validator indices", () => {
      const proposers = state.currentProposers;
      expect(Array.isArray(proposers)).toBe(true);
      expect(proposers.length).toBeGreaterThan(0);
      // Each proposer index should be a valid validator index
      for (const proposer of proposers) {
        expect(proposer).toBeGreaterThanOrEqual(0);
        expect(proposer).toBeLessThan(state.validatorCount);
      }
    });

    it("nextProposers should be an array of validator indices", () => {
      const proposers = state.nextProposers;
      expect(Array.isArray(proposers)).toBe(true);
      expect(proposers.length).toBeGreaterThan(0);
    });

    it("getBeaconProposer should return a valid validator index", () => {
      const proposer = state.getBeaconProposer(state.slot);
      expect(proposer).toBeGreaterThanOrEqual(0);
      expect(proposer).toBeLessThan(state.validatorCount);
    });

    it("decision roots should be 32 bytes each", () => {
      expect(state.previousDecisionRoot.length).toBe(32);
      expect(state.currentDecisionRoot.length).toBe(32);
      expect(state.nextDecisionRoot.length).toBe(32);
    });

    it("getShufflingDecisionRoot should return 32 bytes", () => {
      const decisionRoot = state.getShufflingDecisionRoot(state.epoch);
      expect(decisionRoot.length).toBe(32);
    });
  });

  describe("sync committee cache", () => {
    it("currentSyncCommitteeIndexed should have validatorIndices", () => {
      const indexed = state.currentSyncCommitteeIndexed;
      expect(Array.isArray(indexed.validatorIndices)).toBe(true);
      expect(indexed.validatorIndices.length).toBeGreaterThan(0);
    });

    it("getIndexedSyncCommitteeAtEpoch should return cache", () => {
      const indexed = state.getIndexedSyncCommitteeAtEpoch(state.epoch);
      expect(Array.isArray(indexed.validatorIndices)).toBe(true);
    });

    it("syncProposerReward should be a non-negative number", () => {
      expect(state.syncProposerReward).toBeGreaterThanOrEqual(0);
    });
  });

  describe("serialization", () => {
    it("serialize should produce bytes matching original", () => {
      const serialized = state.serialize();
      expect(serialized.length).toBe(stateBytes.length);
      expect(Buffer.compare(serialized, stateBytes)).toBe(0);
    });

    it("serializedSize should match actual serialized length", () => {
      const size = state.serializedSize();
      const serialized = state.serialize();
      expect(size).toBe(serialized.length);
    });

    it("serializeToBytes should write correct bytes", () => {
      const size = state.serializedSize();
      const output = new Uint8Array(size);
      const bytesWritten = state.serializeToBytes(output, 0);

      expect(bytesWritten).toBe(size);
      expect(Buffer.compare(output, stateBytes)).toBe(0);
    });

    it("serializeValidators should produce valid validator bytes", () => {
      const validatorsBytes = state.serializeValidators();
      // Each validator is 121 bytes in SSZ
      expect(validatorsBytes.length).toBe(state.validatorCount * 121);
    });

    it("serializedValidatorsSize should match validators byte length", () => {
      const size = state.serializedValidatorsSize();
      expect(size).toBe(state.validatorCount * 121);
    });

    it("serializeValidatorsToBytes should write correct bytes", () => {
      const size = state.serializedValidatorsSize();
      const output = new Uint8Array(size);
      const bytesWritten = state.serializeValidatorsToBytes(output, 0);

      expect(bytesWritten).toBe(size);

      const expectedValidators = state.serializeValidators();
      expect(Buffer.compare(output, expectedValidators)).toBe(0);
    });
  }, 10_000); // slow

  /*TODO: This tests passes locally on a long timeout but the worker crashes on GitHub CI.
  / It is also unusual that this takes as long as it does when demo.ts runs nearly instantly.
   Investigate and fix! */
  // describe("hashTreeRoot", () => {
  //   it("hashTreeRoot should match lodestar", () => {
  //     const bindingsRoot = state.hashTreeRoot();
  //     const lodestarRoot = lodestarState.hashTreeRoot();

  //     expect(bindingsRoot).toEqual(lodestarRoot);
  //   }, 120_000); // slow
  // });

  describe("proofs", () => {
    it("getSingleProof should return array of 32-byte nodes", () => {
      // gindex 169 is within the state tree
      const proof = state.getSingleProof(169);
      expect(Array.isArray(proof)).toBe(true);
      for (const node of proof) {
        expect(node.length).toBe(32);
      }
    });

    it("getFinalizedRootProof should return array of 32-byte nodes", () => {
      const proof = state.getFinalizedRootProof();
      expect(Array.isArray(proof)).toBe(true);
      for (const node of proof) {
        expect(node.length).toBe(32);
      }
    });

    it("createMultiProof should return valid compact multi proof", () => {
      // Descriptor for gindex 42
      const descriptor = Uint8Array.from([0x25, 0xe0]);
      const proof = state.createMultiProof(descriptor);

      expect(proof.type).toBe("compactMulti");
      expect(Array.isArray(proof.leaves)).toBe(true);
      expect(proof.descriptor).toBeInstanceOf(Uint8Array);
    });
  });

  describe("voluntary exit validation", () => {
    it("isValidVoluntaryExit should return boolean", () => {
      // Invalid voluntary exit bytes (all zeros)
      const invalidExit = new Uint8Array(112);
      const result = state.isValidVoluntaryExit(invalidExit, false);
      expect(typeof result).toBe("boolean");
    });

    it("getVoluntaryExitValidity should return validity reason", () => {
      // Invalid voluntary exit bytes (all zeros)
      const invalidExit = new Uint8Array(112);
      const result = state.getVoluntaryExitValidity(invalidExit, false);

      const validReasons = [
        "valid",
        "inactive",
        "already_exited",
        "early_epoch",
        "short_time_active",
        "pending_withdrawals",
        "invalid_signature",
      ];
      expect(validReasons).toContain(result);
    });
  });

  describe("unrealized checkpoints", () => {
    it("computeUnrealizedCheckpoints should return checkpoints", () => {
      const result = state.computeUnrealizedCheckpoints();

      expect(result.justifiedCheckpoint).toBeDefined();
      expect(typeof result.justifiedCheckpoint.epoch).toBe("number");
      expect(result.justifiedCheckpoint.root.length).toBe(32);

      expect(result.finalizedCheckpoint).toBeDefined();
      expect(typeof result.finalizedCheckpoint.epoch).toBe("number");
      expect(result.finalizedCheckpoint.root.length).toBe(32);
    });
  });

  describe("proposer rewards", () => {
    it("proposerRewards should have expected structure", () => {
      const rewards = state.proposerRewards;

      expect(typeof rewards.attestations).toBe("bigint");
      expect(typeof rewards.syncAggregate).toBe("bigint");
      expect(typeof rewards.slashing).toBe("bigint");
    });
  });

  describe("clone tracking", () => {
    it("clonedCount should be a non-negative number", () => {
      expect(state.clonedCount).toBeGreaterThanOrEqual(0);
    });

    it("clonedCountWithTransferCache should be a non-negative number", () => {
      expect(state.clonedCountWithTransferCache).toBeGreaterThanOrEqual(0);
    });

    it("createdWithTransferCache should be a boolean", () => {
      expect(typeof state.createdWithTransferCache).toBe("boolean");
    });
  });

  describe("processSlots", () => {
    it("processSlots should advance state by 1 slot", () => {
      const originalSlot = state.slot;
      const newState = state.processSlots(originalSlot + 1);

      expect(newState.slot).toBe(originalSlot + 1);
    });

    it("processSlots with transferCache option should work", () => {
      const originalSlot = state.slot;
      const newState = state.processSlots(originalSlot + 1, {transferCache: true});

      expect(newState.slot).toBe(originalSlot + 1);
      expect(newState.createdWithTransferCache).toBe(true);
    });
  });

  describe("effective balance increments", () => {
    it("getEffectiveBalanceIncrementsZeroInactive should return Uint16Array", () => {
      const increments = state.getEffectiveBalanceIncrementsZeroInactive();
      expect(increments).toBeInstanceOf(Uint16Array);
      expect(increments.length).toBe(state.validatorCount);
    });
  });
});
