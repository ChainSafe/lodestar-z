const std = @import("std");
const testing = std.testing;

pub const vote_tracker = @import("vote_tracker.zig");
pub const compute_deltas = @import("compute_deltas.zig");
pub const proto_array = @import("proto_array.zig");
pub const store = @import("store.zig");
pub const fork_choice = @import("fork_choice.zig");
pub const interface = @import("interface.zig");
pub const safe_blocks = @import("safe_blocks.zig");

pub const ProtoBlock = proto_array.ProtoBlock;
pub const ProtoNode = proto_array.ProtoNode;
pub const ExecutionStatus = proto_array.ExecutionStatus;
pub const DataAvailabilityStatus = proto_array.DataAvailabilityStatus;
pub const PayloadStatus = proto_array.PayloadStatus;
pub const BlockExtraMeta = proto_array.BlockExtraMeta;
pub const LVHExecResponse = proto_array.LVHExecResponse;
pub const LVHValidResponse = proto_array.LVHValidResponse;
pub const LVHInvalidResponse = proto_array.LVHInvalidResponse;
pub const LVHExecErrorCode = proto_array.LVHExecErrorCode;

pub const ProtoArrayError = proto_array.ProtoArrayError;
pub const ForkChoiceError = proto_array.ForkChoiceError;
pub const InvalidBlockCode = proto_array.InvalidBlockCode;
pub const InvalidAttestationCode = proto_array.InvalidAttestationCode;

pub const ProtoArrayStruct = proto_array.ProtoArray;
pub const DEFAULT_PRUNE_THRESHOLD = proto_array.DEFAULT_PRUNE_THRESHOLD;
pub const VariantIndices = proto_array.VariantIndices;
pub const RootContext = proto_array.RootContext;

pub const VoteTracker = vote_tracker.VoteTracker;
pub const Votes = vote_tracker.Votes;
pub const NULL_VOTE_INDEX = vote_tracker.NULL_VOTE_INDEX;

pub const computeDeltas = compute_deltas.computeDeltas;
pub const ComputeDeltasResult = compute_deltas.ComputeDeltasResult;
pub const DeltasCache = compute_deltas.DeltasCache;
pub const EquivocatingIndices = compute_deltas.EquivocatingIndices;
pub const VoteIndex = compute_deltas.VoteIndex;

pub const ForkChoiceStruct = fork_choice.ForkChoice;
pub const HeadResult = fork_choice.HeadResult;

pub const ForkChoiceStore = store.ForkChoiceStore;
pub const Checkpoint = store.Checkpoint;
pub const CheckpointWithPayloadStatus = store.CheckpointWithPayloadStatus;
pub const EffectiveBalanceIncrementsRc = store.EffectiveBalanceIncrementsRc;
pub const JustifiedBalances = store.JustifiedBalances;
pub const JustifiedBalancesGetter = store.JustifiedBalancesGetter;
pub const EventCallback = store.EventCallback;
pub const ForkChoiceStoreEvents = store.ForkChoiceStoreEvents;
pub const computeTotalBalance = store.computeTotalBalance;

pub const EpochDifference = interface.EpochDifference;
pub const AncestorStatus = interface.AncestorStatus;
pub const AncestorResult = interface.AncestorResult;
pub const NotReorgedReason = interface.NotReorgedReason;
pub const ShouldOverrideForkChoiceUpdateResult = interface.ShouldOverrideForkChoiceUpdateResult;
pub const ForkChoiceOpts = interface.ForkChoiceOpts;
pub const UpdateHeadOpt = interface.UpdateHeadOpt;
pub const UpdateAndGetHeadOpt = interface.UpdateAndGetHeadOpt;
pub const UpdateAndGetHeadResult = interface.UpdateAndGetHeadResult;
pub const CheckpointWithPayloadAndBalance = interface.CheckpointWithPayloadAndBalance;
pub const CheckpointWithPayloadAndTotalBalance = interface.CheckpointWithPayloadAndTotalBalance;

pub const getSafeBeaconBlockRoot = safe_blocks.getSafeBeaconBlockRoot;
pub const getSafeExecutionBlockHash = safe_blocks.getSafeExecutionBlockHash;

test {
    testing.refAllDecls(@This());
}
