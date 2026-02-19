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
}

export declare const blsBatch: BlsBatch;
