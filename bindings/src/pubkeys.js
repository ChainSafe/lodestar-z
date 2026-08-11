import bindings from "./bindings.js";

/**
 * Build the JS wrapper around one native pubkey-cache namespace. Each wrapper
 * lazily memoizes PublicKey objects returned by Zig in its own Map.
 *
 * @param {any} native
 * @returns {import("./pubkeys.d.ts").PubkeyCache}
 */
function createPubkeyCache(native) {
  /** @type {Map<number, import("./blst.js").PublicKey>} */
  const pkCache = new Map();

  const cache = {
    get(index) {
      let pk = pkCache.get(index);
      if (pk !== undefined) return pk;
      pk = native.get(index);
      if (pk !== undefined) {
        pkCache.set(index, pk);
      }
      return pk;
    },

    getOrThrow(index) {
      const pk = cache.get(index);
      if (pk === undefined) {
        throw Error(`pubkeyCache: index ${index} not found`);
      }
      return pk;
    },

    getPubkeyBytes(index) {
      return native.getPubkeyBytes(index);
    },

    aggregate(indices) {
      if (indices.length === 1) return cache.getOrThrow(indices[0]);
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

  return cache;
}

export const pubkeyCache = createPubkeyCache(bindings.pubkeys);

/**
 * Draft lock-free cache (v2), exposed alongside v1 for benchmarking.
 * PKIX save/load is not implemented for v2.
 */
export const pubkeyCacheV2 = createPubkeyCache(bindings.pubkeysV2);
