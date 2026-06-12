export interface IndexedSet {
  index: number;
  message: Uint8Array;
  signature: Uint8Array;
}

export interface AggregateSet {
  indices: number[];
  message: Uint8Array;
  signature: Uint8Array;
}

export interface SingleSet {
  publicKey: Uint8Array;
  message: Uint8Array;
  signature: Uint8Array;
}

export interface SameMessageSet {
  index: number;
  signature: Uint8Array;
}

/**
 * Cumulative native-bucketed histogram. `bounds[i]` is the `le` upper bound (seconds)
 * of `counts[i]`, where `counts` are cumulative (count of observations ≤ bounds[i]).
 * The implicit `+Inf` bucket equals `count`. `sum` is the total observed seconds.
 */
export interface NativeHistogram {
  bounds: number[];
  counts: number[];
  sum: number;
  count: number;
}

export interface BlsBatch {
  readonly indexed: 0;
  readonly aggregate: 1;
  readonly single: 2;

  /**
   * Maximum number of sets accepted in a single verify/asyncVerify/asyncVerifySameMessage
   * call. Larger jobs are rejected with a `TooManySets` error; callers must chunk to this
   * size. Mirrors `MAX_AGGREGATE_PER_JOB` in the native library.
   */
  readonly maxSetsPerJob: number;

  verify(kind: 0, sets: IndexedSet[]): boolean;
  verify(kind: 1, sets: AggregateSet[]): boolean;
  verify(kind: 2, sets: SingleSet[]): boolean;

  /**
   * `priority` (default false) routes the job to the worker pool's high lane, drained
   * before any queued low-lane backlog — pass true for latency-sensitive (gossip)
   * verification and false for bulk work (block import / range sync).
   */
  asyncVerify(kind: 0, sets: IndexedSet[], priority?: boolean): Promise<boolean>;
  asyncVerify(kind: 1, sets: AggregateSet[], priority?: boolean): Promise<boolean>;
  asyncVerify(kind: 2, sets: SingleSet[], priority?: boolean): Promise<boolean>;

  asyncVerifySameMessage(sets: SameMessageSet[], message: Uint8Array, priority?: boolean): Promise<boolean>;

  init(maxJobs: number): void;
  /**
   * Advisory backpressure: false when job slots are exhausted OR when in-flight work
   * exceeds the latency budget (`inflightSets >= maxInflightSets`, ≈250ms of queued
   * compute per worker) — work-based, so it trips long before the job-slot pool
   * (sized in jobs, not sets) would.
   */
  canAcceptWork(): boolean;

  /**
   * Real, point-in-time native worker-pool occupancy for metrics/observability.
   * Every field is a measured count (no derived or fabricated values). Returns
   * zeros with `initialized: false` before `init`.
   */
  stats(): {
    initialized: boolean;
    canAcceptWork: boolean;
    /** Worker threads in the pool. */
    workers: number;
    /** Admission capacity (job-pool slot count). */
    maxInflight: number;
    /** Jobs submitted but not yet completed (queued + running + settling). */
    active: number;
    /** Jobs admitted but not yet picked up by a worker (≈ unstable queue_length). */
    queued: number;
    /** Workers currently executing verification (≈ unstable workers_busy). */
    running: number;
    /** Unused job-pool slots. */
    freeSlots: number;
    /** Signature sets in flight (submitted, not yet completed) — work-based saturation. */
    inflightSets: number;
    /** Advisory inflight-sets budget (workers × 256); canAcceptWork trips at this. */
    maxInflightSets: number;
    /** Cumulative worker compute seconds (Σ run_fn). Legacy aggregate: time_seconds_sum. */
    workerTimeSeconds: number;
    /** Queue residency (submit → worker pickup), s. Legacy: queue_job_wait_time_seconds. */
    queueWait: NativeHistogram;
    /** Worker verify compute per sig set, s. Legacy: bls_worker_thread_time_per_sigset_seconds. */
    workerComputePerSigSet: NativeHistogram;
    /** Same-message aggregateWithRandomness time, s. Legacy: aggregate_with_randomness_async_time_seconds. */
    aggregateWithRandomness: NativeHistogram;
    /** Aggregate-kind pubkey aggregation time, s. Legacy: pubkeys_aggregation_main_thread_time_seconds. */
    pubkeysAggregation: NativeHistogram;
  };
}

export declare const blsBatch: BlsBatch;
