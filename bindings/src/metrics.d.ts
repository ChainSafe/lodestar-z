/** Initialize this environment's native state-transition metrics. */
export declare function init(options?: {historical?: boolean}): void;

/** Scrape native state-transition metrics in Prometheus text format. */
export declare function scrapeMetrics(): string;
