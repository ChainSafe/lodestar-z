import type {PublicKey} from "./blst.js";

export interface PubkeyCache {
  /** Get deserialized PublicKey by validator index (cached at JS level) */
  get(index: number): PublicKey | undefined;
  /** Same as get(), but throws if the index is not in the cache */
  getOrThrow(index: number): PublicKey;
  /** Aggregate cached public keys by validator index */
  aggregate(indices: number[]): PublicKey;
  /** Get validator index by pubkey bytes */
  getIndex(pubkey: Uint8Array): number | null;
  /** Set both directions atomically — impl owns the PublicKey.fromBytes() deserialization */
  set(index: number, pubkey: Uint8Array): void;
  /** Number of entries */
  readonly size: number;
  /** Allocated native capacity */
  readonly capacity: number;
  /** Load cache from a PKIX file (clears JS-level cache) */
  load(filepath: string): void;
  /** Clear native and JS-level cache contents */
  reset(): void;
  /** Save cache to a PKIX file */
  save(filepath: string): void;
  /**
   * Pre-allocate native capacity. When a set() outgrows the current capacity, it grows
   * by a fixed step covering ~3 months of worst-case validator registry growth.
   */
  ensureCapacity(capacity: number): void;
}

export declare const pubkeyCache: PubkeyCache;
