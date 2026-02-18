import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {SecretKey} from "../src/blst.js";
import bindings from "../src/index.js";

// Generate deterministic valid BLS keypairs for testing
const keypairs = Array.from({length: 3}, (_, i) => {
  const ikm = new Uint8Array(32);
  ikm[0] = i + 1;
  const sk = SecretKey.fromKeygen(ikm);
  const pk = sk.toPublicKey();
  return {index: i, pubkeyBytes: pk.toBytes()};
});

describe("pubkeys", () => {
  const tempPkixPath = path.join(os.tmpdir(), `lodestar-z-pubkeys-${process.pid}-${Date.now()}.pkix`);

  beforeAll(() => {
    bindings.pubkeys.ensureCapacity(1_000);
  });

  afterAll(() => {
    fs.rmSync(tempPkixPath, {force: true});
  });

  it("set populates both directions and updates size", () => {
    for (const {index, pubkeyBytes} of keypairs) {
      bindings.pubkeys.set(index, pubkeyBytes);
    }
    expect(bindings.pubkeys.size).toBe(keypairs.length);

    for (const {index, pubkeyBytes} of keypairs) {
      expect(bindings.pubkeys.get(index)).toBeDefined();
      expect(bindings.pubkeys.getIndex(pubkeyBytes)).toBe(index);
    }
  });

  it("get returns undefined for out-of-range index", () => {
    expect(bindings.pubkeys.get(0xffffffff)).toBeUndefined();
  });

  it("getIndex returns null for unknown pubkey", () => {
    expect(bindings.pubkeys.getIndex(new Uint8Array(48))).toBeNull();
  });

  it("getIndex throws for invalid pubkey length", () => {
    expect(() => bindings.pubkeys.getIndex(new Uint8Array(47))).toThrow();
  });

  it("save/load roundtrips cache contents", () => {
    bindings.pubkeys.save(tempPkixPath);
    bindings.pubkeys.load(tempPkixPath);

    expect(bindings.pubkeys.size).toBe(keypairs.length);
    for (const {index, pubkeyBytes} of keypairs) {
      expect(bindings.pubkeys.getIndex(pubkeyBytes)).toBe(index);
      expect(bindings.pubkeys.get(index)).toBeDefined();
    }
  });
});
