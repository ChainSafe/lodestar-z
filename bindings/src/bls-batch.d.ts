export interface BlsBatch {
  // ── Sync (main thread, blocking) ────────────────────────────

  /** Batch-verify indexed sets. Returns false if any set is invalid. */
  verifyIndexed(sets: {index: number; message: Uint8Array; signature: Uint8Array}[]): boolean;

  /** Batch-verify aggregate sets. Returns false if any set is invalid. */
  verifyAggregate(sets: {indices: number[]; message: Uint8Array; signature: Uint8Array}[]): boolean;

  /** Batch-verify sets with explicit pubkey bytes. Returns false if any set is invalid. */
  verifySingle(sets: {publicKey: Uint8Array; message: Uint8Array; signature: Uint8Array}[]): boolean;

  // ── Async (worker thread) ───────────────────────────────────

  /** Same as verifyIndexed, dispatched to a worker thread. */
  asyncVerifyIndexed(sets: {index: number; message: Uint8Array; signature: Uint8Array}[]): Promise<boolean>;

  /** Same as verifyAggregate, dispatched to a worker thread. */
  asyncVerifyAggregate(sets: {indices: number[]; message: Uint8Array; signature: Uint8Array}[]): Promise<boolean>;

  /** Same as verifySingle, dispatched to a worker thread. */
  asyncVerifySingle(sets: {publicKey: Uint8Array; message: Uint8Array; signature: Uint8Array}[]): Promise<boolean>;

  /**
   * Same-message optimization: aggregateWithRandomness over all sets, then
   * verify once. Dispatched to a worker thread.
   */
  asyncVerifySameMessage(sets: {index: number; signature: Uint8Array}[], message: Uint8Array): Promise<boolean>;

  // ── Pool management ──────────────────────────────────────────

  /**
   * Pre-allocate the buffer pool.  Call once at startup before dispatching work.
   * Each slot holds up to 128 verification sets.
   * @param maxJobs — maximum number of concurrent async jobs
   */
  init(maxJobs: number): void;

  /**
   * Returns true if the pool has a free buffer slot for another async job.
   * Use this for backpressure before dispatching async work.
   */
  canAcceptWork(): boolean;
}

export declare const blsBatch: BlsBatch;
