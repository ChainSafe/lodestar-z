# Validator Monitor Design

## Overview

The validator monitor tracks on-chain performance of operator-specified validators,
answering four key questions:

1. **"Are my validators making money?"** — balance tracking with epoch-over-epoch deltas
2. **"Are my validators performing duties on time?"** — attestation, proposal, sync committee tracking
3. **"Is something wrong RIGHT NOW?"** — missed duty detection, balance decrease alerts
4. **"What happened historically?"** — rolling epoch summaries with configurable window

## Architecture

```
┌──────────────────────────────────────────────────┐
│                ValidatorMonitor                    │
│                                                    │
│  monitored: HashMap(u64, MonitoredValidator)       │
│  epoch_summaries: BoundedArray(EpochSummary, N)    │
│  config: MonitorConfig                             │
│                                                    │
│  ── Called during block import ──                   │
│  processBlockAttestations(block, state)            │
│  processBlock(block, block_root)                   │
│  processSyncAggregate(block, state)                │
│                                                    │
│  ── Called at epoch boundary ──                     │
│  onEpochTransition(state)                          │
│                                                    │
│  ── Query API ──                                   │
│  getValidatorSummary(index) → ?ValidatorSummary    │
│  getEpochSummary(epoch) → ?EpochSummary            │
│  getEffectivenessScore(index) → ?f64               │
│  scrapeMetrics() → void                            │
└──────────────────────────────────────────────────┘
        │
        ├── Prometheus metrics (labeled by validator index)
        │     validator_monitor_attestation_delay
        │     validator_monitor_attestation_hit
        │     validator_monitor_head_correct
        │     validator_monitor_balance_gwei
        │     validator_monitor_balance_delta_gwei
        │     validator_monitor_effectiveness
        │     validator_monitor_blocks_proposed
        │     validator_monitor_blocks_missed
        │     validator_monitor_sync_participation
        │
        └── REST API: GET /eth/v1/lodestar/validator_monitor
```

## Per-Validator Tracking

For each monitored validator per epoch:

### Attestation Performance
- **Inclusion delay**: slots between attestation slot and inclusion slot (histogram: 0, 1, 2, 3+)
- **Head vote accuracy**: did the attestation's beacon_block_root match what became canonical?
- **Source vote accuracy**: was the source checkpoint correct?
- **Target vote accuracy**: was the target checkpoint correct?
- **Hit/miss**: was an attestation included at all?

### Block Proposals
- **Proposed**: did the validator produce a block when scheduled?
- **Missed**: was the validator expected to propose but didn't?
- **Block root**: the root of any proposed block

### Sync Committee
- **Participation**: did the validator's bit appear in the sync aggregate?
- **Hit rate**: fraction of expected sync committee duties fulfilled

### Balance
- **Current balance**: actual validator balance in gwei
- **Effective balance**: effective balance (used for rewards calc)
- **Balance delta**: change vs. previous epoch (positive = reward, negative = penalty)
- **Cumulative reward**: total gwei earned/lost since monitoring started

## Effectiveness Score

Single 0–100 number combining:
- Attestation inclusion rate (40% weight)
- Average inclusion delay penalty (20% weight) — 1.0 for delay=1, 0.5 for delay=2, etc.
- Head vote accuracy (15% weight)
- Target vote accuracy (15% weight)
- Source vote accuracy (10% weight)

Formula:
```
score = 100 * (
    0.40 * (included / expected) +
    0.20 * avg(1 / inclusion_delay) +
    0.15 * (head_correct / included) +
    0.15 * (target_correct / included) +
    0.10 * (source_correct / included)
)
```

A perfect validator scores 100. Missing attestations drops the score fastest.

## Epoch Summary

Aggregated across all monitored validators:
- Attestation hit rate, head/source/target accuracy rates
- Average inclusion delay
- Blocks proposed vs. missed
- Sync committee participation rate
- Total balance delta (gwei)

Rolling window of N epochs (configurable, default 64).

## Beyond Lodestar-TS and Lighthouse

### Novel features in this implementation:
1. **Effectiveness score** — single number for "how well is this validator doing?"
2. **Inclusion delay histogram** — not just average, but distribution (0/1/2/3+ slots)
3. **Cumulative reward tracking** — total since monitoring started
4. **JSON-exportable epoch summaries** — via REST API
5. **Configurable rolling window** — operators choose how much history to keep

### Future work (not in initial implementation):
- Relative performance vs. network average
- Reorg impact tracking
- SSE events for real-time alerts
- MEV attribution (builder bid vs. local value)
- Annualized yield estimate
