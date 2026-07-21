import bindings from "./bindings.js";

const native = bindings.pubkeys;

/** @type {Map<number, import("./blst.js").PublicKey>} */
const pkCache = new Map();

/** @type {import("./pubkeys.d.ts").PubkeyCache} */
export const pubkeyCache = {
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
    const pk = pubkeyCache.get(index);
    if (pk === undefined) {
      throw Error(`pubkeyCache: index ${index} not found`);
    }
    return pk;
  },

  aggregate(indices) {
    if (indices.length === 1) return pubkeyCache.getOrThrow(indices[0]);
    return native.aggregate(indices);
  },

  getIndex(pubkey) {
    return native.getIndex(pubkey);
  },

  set(index, pubkey) {
    native.set(index, pubkey);
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
