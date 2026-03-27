# Gossip Verification Delta Analysis

## Overview

Audit of BLS signature verification and validation checks in lodestar-z gossip
handlers vs TS Lodestar reference implementation.

**Date:** 2026-03-27
**Branch:** fix/gossip-verification
**Status:** All gossip handlers are missing BLS signature verification.

## Per-Message-Type Delta

### beacon_block
- **TS Lodestar:** `getBlockProposerSignatureSet` → single BLS verify (proposer sig)
- **lodestar-z:** No BLS check. Phase 1 checks slot/proposer/parent. Phase 2 does STFN (which has its own BLS during processBlock, but that's too late for gossip scoring).
- **Gap:** MISSING proposer signature verification at gossip level
- **Fix:** Verify proposer signature after Phase 1, before Phase 2 import

### beacon_attestation (SingleAttestation in Electra)
- **TS Lodestar:** Constructs indexed attestation, verifies aggregate BLS sig over AttestationData
- **lodestar-z:** No BLS check. No per-validator dedup (seenAttesters).
- **Gap:** MISSING attestation signature, MISSING per-validator dedup
- **Fix:** Verify single-validator attestation sig (SingleAttestation = 1 validator)

### beacon_aggregate_and_proof
- **TS Lodestar:** 3 signature sets: selection proof, aggregator sig, aggregate attestation sig
- **lodestar-z:** No BLS check. No committee membership validation.
- **Gap:** MISSING all 3 signatures, MISSING aggregator committee membership check
- **Fix:** Verify all 3 signatures after Phase 1

### voluntary_exit
- **TS Lodestar:** `getVoluntaryExitSignatureSet` → single BLS verify, plus `getVoluntaryExitValidity` (process_voluntary_exit checks)
- **lodestar-z:** No BLS check. Has basic bounds but missing seen-cache dedup in gossip_handler (gossip_validation.zig has it but gossip_handler.zig doesn't use the full validation context).
- **Gap:** MISSING exit signature verification
- **Fix:** Verify validator signature over VoluntaryExit

### proposer_slashing
- **TS Lodestar:** `getProposerSlashingSignatureSets` → 2 header signatures + `assertValidProposerSlashing`
- **lodestar-z:** No BLS check. Has basic structural checks (same slot, different body roots).
- **Gap:** MISSING both header signature verifications
- **Fix:** Verify both signed header signatures

### attester_slashing
- **TS Lodestar:** `getAttesterSlashingSignatureSets` → 2 indexed attestation signatures + `assertValidAttesterSlashing`
- **lodestar-z:** No BLS check. Checks is_slashable but not signatures.
- **Gap:** MISSING both indexed attestation signature verifications
- **Fix:** Verify both indexed attestation signatures

### bls_to_execution_change
- **TS Lodestar:** `getBlsToExecutionChangeSignatureSet` → single BLS verify + `isValidBlsToExecutionChange`
- **lodestar-z:** No BLS check. Basic bounds check only.
- **Gap:** MISSING validator signature over BLSToExecutionChange
- **Fix:** Verify BLS signature

### sync_committee (SyncCommitteeMessage)
- **TS Lodestar:** `getSyncCommitteeSignatureSet` → single BLS verify + subnet/committee membership validation
- **lodestar-z:** No BLS check. Basic bounds only. Missing subnet validation.
- **Gap:** MISSING participant signature, MISSING subnet membership check
- **Fix:** Verify participant signature

### sync_committee_contribution_and_proof
- **TS Lodestar:** Selection proof + contribution signature + aggregator signature
- **lodestar-z:** No BLS check. Basic bounds only.
- **Gap:** MISSING all signatures
- **Fix:** Add signature verification (deferred - needs sync committee caches)

## Validation Ordering

TS Lodestar order:
1. Cheap checks (seen cache, slot range, committee bounds) — < 1ms
2. State access (regen pre-state, shuffling lookup)
3. BLS signature verification — expensive, done last
4. Post-verification seen-cache updates (race-condition guard)

lodestar-z order:
1. Cheap checks (seen cache, slot range, proposer) — ✓ matches
2. **No BLS verification** — ✗ gap
3. Direct import — ✗ should not import unverified messages

## Architecture Decision

Rather than adding BLS verification inline in each gossip handler (which would
require the handler to hold references to BeaconConfig + EpochCache), we add
type-erased verification callbacks that the BeaconNode provides. This maintains
the clean separation between gossip_handler (type-erased) and beacon_node
(full state access).

The callbacks receive raw SSZ bytes and return bool (signature valid or not).
This lets the node-side code construct signature sets using its state caches.
