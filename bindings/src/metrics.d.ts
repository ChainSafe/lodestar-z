export type StateHashTreeRootSource =
  | "state_transition"
  | "block_transition"
  | "prepare_next_slot"
  | "prepare_next_epoch"
  | "regen_state"
  | "compute_new_state_root";

/** Initialize native state-transition metrics. */
export declare function init(): void;

/** Record an externally timed state hash-tree-root operation. */
export declare function observeStateHashTreeRoot(source: StateHashTreeRootSource, seconds: number): void;

/** Scrape all native metrics in Prometheus text format. */
export declare function scrapeMetrics(): string;

/** Scrape only native state-transition metrics in Prometheus text format. */
export declare function scrapeStateTransitionMetrics(): string;

/** Scrape only native validator-monitor metrics in Prometheus text format. */
export declare function scrapeValidatorMonitorMetrics(): string;

/**
 * Register a validator index with the native validator monitor. Metrics
 * are recorded for registered validators on every epoch transition.
 */
export declare function registerLocalValidator(index: number): void;

/**
 * Remove a validator index from the native validator monitor, so its
 * `validator_monitor_*` status metrics stop being recorded. Mirrors the pruning
 * of stale registrations in lodestar's validator monitor.
 */
export declare function unregisterLocalValidator(index: number): void;
