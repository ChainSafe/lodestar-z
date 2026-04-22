const zapi = @import("zapi");
const js = zapi.js;
const napi = zapi.napi;

pub fn wrap(comptime T: type, value: napi.Value) T {
    return .{ .val = value };
}

pub const Fork = js.Object(struct {
    previousVersion: js.Uint8Array,
    currentVersion: js.Uint8Array,
    epoch: js.Number,
});

pub const Eth1Data = js.Object(struct {
    depositRoot: js.Uint8Array,
    depositCount: js.Number,
    blockHash: js.Uint8Array,
});

pub const BeaconBlockHeader = js.Object(struct {
    slot: js.Number,
    proposerIndex: js.Number,
    parentRoot: js.Uint8Array,
    stateRoot: js.Uint8Array,
    bodyRoot: js.Uint8Array,
});

pub const Checkpoint = js.Object(struct {
    epoch: js.Number,
    root: js.Uint8Array,
});

pub const SyncCommittee = js.Object(struct {
    pubkeys: js.Array,
    aggregatePubkey: js.Uint8Array,
});

pub const IndexedSyncCommittee = js.Object(struct {
    validatorIndices: js.Uint32Array,
});

pub const IndexedSyncCommitteeWithMap = js.Object(struct {
    validatorIndices: js.Uint32Array,
    validatorIndexMap: js.Value,
});

pub const Validator = js.Object(struct {
    pubkey: js.Uint8Array,
    withdrawalCredentials: js.Uint8Array,
    effectiveBalance: js.Number,
    slashed: js.Boolean,
    activationEligibilityEpoch: js.Number,
    activationEpoch: js.Number,
    exitEpoch: js.Number,
    withdrawableEpoch: js.Number,
});

pub const ProposerRewards = js.Object(struct {
    attestations: js.BigInt,
    syncAggregate: js.BigInt,
    slashing: js.BigInt,
});

pub const MultiProof = js.Object(struct {
    type: js.String,
    leaves: js.Array,
    descriptor: js.Uint8Array,
});

pub const UnrealizedCheckpoints = js.Object(struct {
    justifiedCheckpoint: Checkpoint,
    finalizedCheckpoint: Checkpoint,
});
