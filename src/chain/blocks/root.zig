//! Block import pipeline — modular verification and import stages.
//!
//! This module replaces the monolithic block import in chain.zig with
//! a staged pipeline matching TS Lodestar's architecture:
//!
//! ┌──────────────┐
//! │ BlockInput   │
//! └──────┬───────┘
//!        │
//! ┌──────▼──────���┐
//! │ verifySanity │ slot, parent, duplicate, finalized
//! └──────┬───────┘
//!        │
//! ┌──────▼───────┐
//! │ getPreState  │ via queued regen
//! └──────┬───────┘
//!        │
//! ┌──────▼───────┐
//! │  verifyDA    │ blob/column availability
//! └──────┬───────┘
//!        │
//! ┌──────▼───────────────��
//! │ executeSTF           │ processSlots + processBlock + batch BLS verify
//! └──────┬───────────────┘
//!        │
//! ┌──────▼───────────────┐
//! │ verifyExecution      │ engine_newPayload
//! └──��───┬───────────────┘
//!        │
//! ┌──────▼───────────────┐
//! │ importBlock          │ fork choice, DB, caches, events
//! └──────┬───────────────┘
//!        │
//! ┌──────▼───────┐
//! │ ImportResult │
//! └──────────────┘
//!
//! Each stage is a separate file for testability and clarity.
//! The pipeline orchestrator (pipeline.zig) wires them together.

const std = @import("std");

// -- Pipeline types (shared vocabulary) --
pub const types = @import("types.zig");

// -- Pipeline stages --
pub const verify_sanity = @import("verify_sanity.zig");
pub const verify_signatures = @import("verify_signatures.zig");
pub const verify_data_availability = @import("verify_data_availability.zig");
pub const execute_state_transition = @import("execute_state_transition.zig");
pub const verify_execution = @import("verify_execution.zig");
pub const import_block = @import("import_block.zig");

// -- Pipeline orchestrator --
pub const pipeline = @import("pipeline.zig");

// -- Primary type re-exports for convenience --
pub const BlockInput = types.BlockInput;
pub const BlockSource = types.BlockSource;
pub const ImportBlockOpts = types.ImportBlockOpts;
pub const ImportResult = types.ImportResult;
pub const VerifiedBlock = types.VerifiedBlock;
pub const ExecutionStatus = types.ExecutionStatus;
pub const DataAvailabilityStatus = types.DataAvailabilityStatus;
pub const BlockImportError = types.BlockImportError;
pub const BatchBlockResult = types.BatchBlockResult;
pub const SanityResult = types.SanityResult;
pub const SegmentExecStatus = types.SegmentExecStatus;

// -- Stage-specific type re-exports --
pub const SanityOutcome = verify_sanity.SanityOutcome;
pub const SignatureVerificationResult = verify_signatures.SignatureVerificationResult;
pub const ExecutionVerifier = verify_execution.ExecutionVerifier;
pub const ImportContext = import_block.ImportContext;
pub const PipelineContext = pipeline.PipelineContext;
pub const StfResult = execute_state_transition.StfResult;

// -- Public API --
pub const processBlock = pipeline.processBlock;
pub const processBlockBatch = pipeline.processBlockBatch;
pub const verifySanity = verify_sanity.verifySanity;
pub const verifyDataAvailability = verify_data_availability.verifyDataAvailability;
pub const verifyExecutionPayload = verify_execution.verifyExecutionPayload;
pub const importVerifiedBlock = import_block.importVerifiedBlock;
pub const shouldVerifySignatures = verify_signatures.shouldVerifySignatures;
pub const createBlockBatchVerifier = verify_signatures.createBlockBatchVerifier;
pub const finalizeBatchVerification = verify_signatures.finalizeBatchVerification;
pub const executeStateTransition = execute_state_transition.executeStateTransition;

// -- Constants --
pub const BLOB_AVAILABILITY_TIMEOUT_MS = verify_data_availability.BLOB_AVAILABILITY_TIMEOUT_MS;

test {
    std.testing.refAllDecls(@This());
}
