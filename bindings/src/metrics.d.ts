/** Initialize native state-transition metrics. */
export declare function init(): void;

/** Scrape all native metrics in Prometheus text format. */
export declare function scrapeMetrics(): string;

/** Scrape only native state-transition metrics in Prometheus text format. */
export declare function scrapeStateTransitionMetrics(): string;

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
