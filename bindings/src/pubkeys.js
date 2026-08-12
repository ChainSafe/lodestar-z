import bindings from "./bindings.js";

const native = bindings.pubkeys;

/** @type {Map<number, import("./blst.js").PublicKey>} */
const pkCache = new Map();

/** @type {import("./pubkeys.d.ts").PubkeyCache} */
export const pubkeyCache = {
  /**
   * Legacy: prefer verification by index (blst.verifyIndexedSignatureSets)
   * on hot paths; retained for consumers that need a JS PublicKey object.
   */
  get(index) {
    let pk = pkCache.get(index);
    if (pk !== undefined) return pk;
    pk = native.get(index);
    if (pk !== undefined) {
      pkCache.set(index, pk);
    }
    return pk;
  },

  /** Legacy: see get(). */
  getOrThrow(index) {
    const pk = pubkeyCache.get(index);
    if (pk === undefined) {
      throw Error(`pubkeyCache: index ${index} not found`);
    }
    return pk;
  },

  getPubkeyBytes(index) {
    return native.getPubkeyBytes(index);
  },

  getPubkeyBytesOrThrow(index) {
     const pubkey = native.getPubkeyBytes(index);
     if (pubkey === undefined) {
       throw new Error(`pubkeyCache: index ${index} not found`);
     }

     return pubkey;
   },

  aggregate(indices) {
    return native.aggregate(indices);
  },

  getIndex(pubkey) {
    return native.getIndex(pubkey);
  },

  append(index, pubkey) {
    native.append(index, pubkey);
  },

  syncPubkeys(validators) {
    native.syncPubkeys(validators);
  },

  get size() {
    return native.size();
  },

  get capacity() {
    return native.capacity();
  },

  load(filepath, maxCapacity) {
    native.load(filepath, maxCapacity);
    pkCache.clear();
  },

  reset() {
    native.reset();
    pkCache.clear();
  },

  save(filepath) {
    native.save(filepath);
  },

  ensureCapacity(capacity) {
    native.ensureCapacity(capacity);
  },
};
