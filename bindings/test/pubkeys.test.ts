import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {SecretKey} from "../src/blst.js";
import {pubkeyCache} from "../src/pubkeys.js";

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
    pubkeyCache.ensureCapacity(1_000);
  });

  afterAll(() => {
    fs.rmSync(tempPkixPath, {force: true});
  });

  it("set populates both directions and updates size", () => {
    for (const {index, pubkeyBytes} of keypairs) {
      pubkeyCache.set(index, pubkeyBytes);
    }
    expect(pubkeyCache.size).toBe(keypairs.length);

    for (const {index, pubkeyBytes} of keypairs) {
      expect(pubkeyCache.get(index)).toBeDefined();
      expect(pubkeyCache.getIndex(pubkeyBytes)).toBe(index);
    }
  });

  it("get returns the same cached object on repeated calls", () => {
    const pk1 = pubkeyCache.get(0);
    const pk2 = pubkeyCache.get(0);
    expect(pk1).toBe(pk2);
  });

  it("get returns undefined for out-of-range index", () => {
    expect(pubkeyCache.get(0xffffffff)).toBeUndefined();
  });

  it("getIndex returns null for unknown pubkey", () => {
    expect(pubkeyCache.getIndex(new Uint8Array(48))).toBeNull();
  });

  it("getIndex throws for invalid pubkey length", () => {
    expect(() => pubkeyCache.getIndex(new Uint8Array(47))).toThrow();
  });

  it("set invalidates cached JS object", () => {
    const before = pubkeyCache.get(0);
    pubkeyCache.set(0, keypairs[0].pubkeyBytes);
    const after = pubkeyCache.get(0);
    expect(before).not.toBe(after);
  });

  it("save/load roundtrips cache contents", () => {
    pubkeyCache.save(tempPkixPath);
    pubkeyCache.load(tempPkixPath);

    expect(pubkeyCache.size).toBe(keypairs.length);
    for (const {index, pubkeyBytes} of keypairs) {
      expect(pubkeyCache.getIndex(pubkeyBytes)).toBe(index);
      expect(pubkeyCache.get(index)).toBeDefined();
    }
  });

  it("load clears JS-level cache", () => {
    const before = pubkeyCache.get(0);
    pubkeyCache.save(tempPkixPath);
    pubkeyCache.load(tempPkixPath);
    const after = pubkeyCache.get(0);
    expect(before).not.toBe(after);
  });
});
