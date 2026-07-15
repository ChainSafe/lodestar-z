import bindings from "./bindings.js";

const native = bindings.pubkeys;

/** Create a cache whose native and JS storage belongs to one validator registry. */
export function createPubkeyCache() {
  const nativeCache = new native.PubkeyCache();
  /** @type {Map<number, import("./blst.js").PublicKey>} */
  const pkCache = new Map();

  /** @type {import("./pubkeys.d.ts").PubkeyCache} */
  const pubkeyCache = {
    createBeaconStateView(bytes) {
      return bindings.BeaconStateView.createFromBytes(bytes, nativeCache);
    },

    get(index) {
      let pk = pkCache.get(index);
      if (pk !== undefined) return pk;
      pk = nativeCache.get(index);
      if (pk !== undefined) {
        pkCache.set(index, pk);
      }
      return pk;
    },

    getOrThrow(index) {
      const pk = pubkeyCache.get(index);
      if (pk === undefined) {
        throw Error(`pubkeyCache: index ${index} not found`);
      }
      return pk;
    },

    aggregate(indices) {
      if (indices.length === 1) return pubkeyCache.getOrThrow(indices[0]);
      return nativeCache.aggregate(indices);
    },

    getIndex(pubkey) {
      return nativeCache.getIndex(pubkey);
    },

    set(index, pubkey) {
      nativeCache.set(index, pubkey);
      pkCache.delete(index);
    },

    get size() {
      return nativeCache.size;
    },

    get capacity() {
      return nativeCache.capacity;
    },

    load(filepath) {
      pkCache.clear();
      nativeCache.load(filepath);
    },

    reset() {
      pkCache.clear();
      nativeCache.reset();
    },

    save(filepath) {
      nativeCache.save(filepath);
    },

    ensureCapacity(capacity) {
      nativeCache.ensureCapacity(capacity);
    },
  };

  return pubkeyCache;
}
