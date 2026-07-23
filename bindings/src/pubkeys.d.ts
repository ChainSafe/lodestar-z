import type {PublicKey} from "./blst.js";

export interface PubkeyCache {
  /** Get a cached, deserialized PublicKey. */
  get(index: number): PublicKey | undefined;
  /** Same as get(), but throws if the index is not in the cache */
  getOrThrow(index: number): PublicKey;
  /** Aggregate cached public keys by validator index */
  aggregate(indices: number[]): PublicKey;
  /** Get validator index by pubkey bytes */
  getIndex(pubkey: Uint8Array): number | null;
  /** Append at the next index. Exact replays are no-ops; invalid, conflicting, duplicate, or sparse entries throw. */
  append(index: number, pubkey: Uint8Array): void;
  /** Current number of cached entries. */
  readonly size: number;
  /** Number of entries the current native allocation can hold without growing. */
  readonly capacity: number;
  /**
   * Load a compatible PKIX file from the control environment while no workers are using the cache.
   * The explicit capacity limit bounds both the entry count and native allocation;
   * spare capacity recorded in the file is discarded above this limit.
   */
  load(filepath: string, maxCapacity: number): void;
  /** Testing-only reset from the control environment while no workers are using the cache. */
  reset(): void;
  /** Save from the control environment. */
  save(filepath: string): void;
  /** Reserve native capacity. This may grow an already populated cache. */
  ensureCapacity(capacity: number): void;
}

export declare const pubkeyCache: PubkeyCache;
