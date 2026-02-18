import type {PublicKey} from "./blst.js";

export interface PubkeyCache {
  /** Get deserialized PublicKey by validator index (cached at JS level) */
  get(index: number): PublicKey | undefined;
  /** Get validator index by pubkey bytes */
  getIndex(pubkey: Uint8Array): number | null;
  /** Set both directions atomically — impl owns the PublicKey.fromBytes() deserialization */
  set(index: number, pubkey: Uint8Array): void;
  /** Number of entries */
  readonly size: number;
  /** Load cache from a PKIX file (clears JS-level cache) */
  load(filepath: string): void;
  /** Save cache to a PKIX file */
  save(filepath: string): void;
  /** Pre-allocate native capacity */
  ensureCapacity(capacity: number): void;
}

export declare const pubkeyCache: PubkeyCache;
