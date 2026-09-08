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

/** Scrape native state-transition metrics in Prometheus text format. */
export declare function scrapeMetrics(): string;
