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

  getIndex(pubkey) {
    return native.getIndex(pubkey);
  },

  set(index, pubkey) {
    native.set(index, pubkey);
    // Invalidate cached JS object so next get() picks up the new native value
    pkCache.delete(index);
  },

  get size() {
    return native.size;
  },

  load(filepath) {
    pkCache.clear();
    native.load(filepath);
  },

  save(filepath) {
    native.save(filepath);
  },

  ensureCapacity(capacity) {
    native.ensureCapacity(capacity);
  },
};
