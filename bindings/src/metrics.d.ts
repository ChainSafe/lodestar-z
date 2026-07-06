/** Initialize native state-transition metrics. */
export declare function init(): void;

/** Scrape native state-transition metrics in Prometheus text format. */
export declare function scrapeMetrics(): string;

/**
 * Register a validator index with the native validator monitor. Metrics
 * are recorded for registered validators on every epoch transition.
 */
export declare function registerLocalValidator(index: number): void;
