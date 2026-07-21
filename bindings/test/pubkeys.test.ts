import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {ssz} from "@lodestar/types";
import {afterAll, beforeEach, describe, expect, it} from "vitest";
import {SecretKey, aggregatePublicKeys} from "../src/blst.js";
import bindings from "../src/index.js";
import {pubkeyCache} from "../src/pubkeys.js";

// Generate deterministic valid BLS keypairs for testing
const keypairs = Array.from({length: 3}, (_, i) => {
  const ikm = new Uint8Array(32);
  ikm[0] = i + 1;
  const sk = SecretKey.fromKeygen(ikm);
  const pk = sk.toPublicKey();
  return {index: i, pubkeyBytes: pk.toBytes()};
});

const PKIX_HEADER_SIZE = 40;
const PKIX_HEADER_CHECKSUM_OFFSET = 32;
const PKIX_ENTRY_SIZE = 48 + 96;
const canEnforceDirectoryPermissions = typeof process.getuid === "function" && process.getuid() !== 0;

function seedCache(count = keypairs.length): void {
  pubkeyCache.reset();
  pubkeyCache.ensureCapacity(2_000);
  for (const {index, pubkeyBytes} of keypairs.slice(0, count)) {
    pubkeyCache.set(index, pubkeyBytes);
  }
}

function expectCacheContents(count = keypairs.length): void {
  expect(pubkeyCache.size).toBe(count);
  for (const {index, pubkeyBytes} of keypairs.slice(0, count)) {
    expect(pubkeyCache.getIndex(pubkeyBytes)).toBe(index);
    expect(pubkeyCache.getOrThrow(index).toBytes()).toEqual(pubkeyBytes);
  }
  expect(pubkeyCache.get(count)).toBeUndefined();
}

describe("pubkeys", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "lodestar-z-pubkeys-"));
  const tempPkixPath = path.join(tempDir, "cache.pkix");

  function expectInvalidFileToPreserveCache(name: string, contents: Uint8Array): void {
    const invalidPath = path.join(tempDir, `${name}.pkix`);
    fs.writeFileSync(invalidPath, contents);

    expect(() => pubkeyCache.load(invalidPath, pubkeyCache.capacity)).toThrow();
    expectCacheContents();
  }

  beforeEach(() => {
    seedCache();
  });

  afterAll(() => {
    fs.rmSync(tempDir, {force: true, recursive: true});
  });

  it("set populates both directions and updates size", () => {
    pubkeyCache.reset();
    for (const {index, pubkeyBytes} of keypairs) {
      pubkeyCache.set(index, pubkeyBytes);
    }
    expect(pubkeyCache.size).toBe(keypairs.length);

    for (const {index, pubkeyBytes} of keypairs) {
      expect(pubkeyCache.get(index)).toBeDefined();
      expect(pubkeyCache.getIndex(pubkeyBytes)).toBe(index);
    }
  });

  it("get caches deserialized values", () => {
    const pk1 = pubkeyCache.getOrThrow(0);
    const pk2 = pubkeyCache.getOrThrow(0);
    expect(pk1).toBe(pk2);
  });

  it("aggregates cached pubkeys by index", () => {
    const indices = [0, 1, 2];
    const expected = aggregatePublicKeys(indices.map((index) => pubkeyCache.getOrThrow(index)));
    expect(pubkeyCache.aggregate(indices).toBytes()).toEqual(expected.toBytes());
  });

  it("returns the cached pubkey for a single-key aggregate", () => {
    expect(pubkeyCache.aggregate([1]).toBytes()).toEqual(pubkeyCache.getOrThrow(1).toBytes());
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

  it("ignores sets for already-cached indices", () => {
    const before = pubkeyCache.getOrThrow(0);
    pubkeyCache.set(0, keypairs[1].pubkeyBytes);
    pubkeyCache.set(0, new Uint8Array(1));

    const after = pubkeyCache.getOrThrow(0);
    expect(after).toBe(before);
    expect(after.toBytes()).toEqual(keypairs[0].pubkeyBytes);
  });

  it("reset invalidates cached values", () => {
    const before = pubkeyCache.getOrThrow(0);

    pubkeyCache.reset();
    pubkeyCache.set(0, keypairs[1].pubkeyBytes);

    const after = pubkeyCache.getOrThrow(0);
    expect(after).not.toBe(before);
    expect(after.toBytes()).toEqual(keypairs[1].pubkeyBytes);
  });

  it("save/load roundtrips cache contents", () => {
    const before = pubkeyCache.getOrThrow(0);
    pubkeyCache.save(tempPkixPath);
    pubkeyCache.load(tempPkixPath, pubkeyCache.capacity);

    expectCacheContents();
    expect(pubkeyCache.getOrThrow(0)).not.toBe(before);
  });

  it("allows control load/reset while a BeaconStateView retains the cache", () => {
    pubkeyCache.save(tempPkixPath);
    bindings.pool.ensureCapacity(100_000);
    const view = bindings.BeaconStateView.createFromBytes(
      ssz.phase0.BeaconState.serialize(ssz.phase0.BeaconState.defaultValue())
    );

    pubkeyCache.reset();
    expect(pubkeyCache.size).toBe(0);
    pubkeyCache.load(tempPkixPath, 2_000);

    expectCacheContents();
    expect(view.validatorCount).toBe(0);
  });

  it.runIf(process.platform === "linux")("save/load preserves a path longer than the former stack buffer", () => {
    let longDirectory = tempDir;
    for (let i = 0; i < 10; i++) {
      longDirectory = path.join(longDirectory, `${i.toString().padStart(2, "0")}-${"x".repeat(110)}`);
    }
    fs.mkdirSync(longDirectory, {recursive: true});
    const longPkixPath = path.join(longDirectory, "cache.pkix");
    expect(Buffer.byteLength(longPkixPath)).toBeGreaterThan(1_023);

    seedCache();
    pubkeyCache.save(longPkixPath);
    expect(fs.existsSync(longPkixPath)).toBe(true);

    seedCache(1);
    pubkeyCache.load(longPkixPath, 2_000);
    expectCacheContents();
  });

  it("rejects a snapshot whose entries exceed the caller's allocation limit", () => {
    pubkeyCache.save(tempPkixPath);

    expect(() => pubkeyCache.load(tempPkixPath, pubkeyCache.size - 1)).toThrow();
    expectCacheContents();
  });

  it("discards encoded spare capacity above the caller's allocation limit", () => {
    pubkeyCache.save(tempPkixPath);

    const entryCount = pubkeyCache.size;
    expect(pubkeyCache.capacity).toBeGreaterThan(entryCount);
    pubkeyCache.load(tempPkixPath, entryCount);

    expect(pubkeyCache.capacity).toBe(entryCount);
    expectCacheContents();
    // Restore the suite's shared reservation after exercising a deliberately
    // smaller load limit.
    pubkeyCache.ensureCapacity(2_000);
  });

  it("writes a self-consistent versioned PKIX header", () => {
    pubkeyCache.save(tempPkixPath);
    const file = fs.readFileSync(tempPkixPath);
    const count = file.readUInt32LE(16);
    const cacheCapacity = file.readUInt32LE(20);

    expect(file.subarray(0, 4).toString("ascii")).toBe("PKIX");
    expect(file.readUInt32LE(4)).toBe(5);
    expect(count).toBe(keypairs.length);
    expect(cacheCapacity).toBeGreaterThanOrEqual(count);
    expect(file.length).toBe(PKIX_HEADER_SIZE + count * PKIX_ENTRY_SIZE);
  });

  it("load replaces values observed through the wrapper", () => {
    pubkeyCache.save(tempPkixPath);

    pubkeyCache.reset();
    pubkeyCache.set(0, keypairs[1].pubkeyBytes);
    expect(pubkeyCache.getOrThrow(0).toBytes()).toEqual(keypairs[1].pubkeyBytes);

    pubkeyCache.load(tempPkixPath, pubkeyCache.capacity);
    expect(pubkeyCache.getOrThrow(0).toBytes()).toEqual(keypairs[0].pubkeyBytes);
  });

  it.each([
    [
      "magic",
      (bytes: Buffer) => {
        bytes[0] ^= 0xff;
      },
    ],
    ["format version", (bytes: Buffer) => bytes.writeUInt32LE(4, 4)],
    [
      "ABI tag",
      (bytes: Buffer) => {
        bytes[8] ^= 0xff;
      },
    ],
  ] as const)("rejects an incompatible %s without replacing the live cache", (name, corrupt) => {
    pubkeyCache.save(tempPkixPath);
    const invalid = Buffer.from(fs.readFileSync(tempPkixPath));
    corrupt(invalid);

    expectInvalidFileToPreserveCache(name.replaceAll(" ", "-"), invalid);
  });

  it("rejects the old 12-byte PKIX header without replacing the live cache", () => {
    const legacyHeader = Buffer.alloc(12);
    legacyHeader.write("PKIX", 0, "ascii");
    legacyHeader.writeUInt32LE(keypairs.length, 4);
    legacyHeader.writeUInt32LE(1_000, 8);

    expectInvalidFileToPreserveCache("legacy-header", legacyHeader);
  });

  it("rejects a corrupted header checksum without replacing the live cache", () => {
    pubkeyCache.save(tempPkixPath);
    const invalid = Buffer.from(fs.readFileSync(tempPkixPath));
    invalid[PKIX_HEADER_CHECKSUM_OFFSET] ^= 0xff;

    expectInvalidFileToPreserveCache("header-checksum", invalid);
  });

  it("rejects payload corruption without replacing the live cache", () => {
    pubkeyCache.save(tempPkixPath);
    const invalid = Buffer.from(fs.readFileSync(tempPkixPath));
    expect(invalid.length).toBeGreaterThan(PKIX_HEADER_SIZE);
    invalid[PKIX_HEADER_SIZE] ^= 0xff;

    expectInvalidFileToPreserveCache("payload", invalid);
  });

  it.each([
    ["truncated header", (bytes: Buffer) => bytes.subarray(0, PKIX_HEADER_SIZE - 1)],
    ["truncated payload", (bytes: Buffer) => bytes.subarray(0, bytes.length - 1)],
    ["extended file", (bytes: Buffer) => Buffer.concat([bytes, Buffer.from([0])])],
  ] as const)("rejects a %s without replacing the live cache", (name, corrupt) => {
    pubkeyCache.save(tempPkixPath);
    const invalid = corrupt(fs.readFileSync(tempPkixPath));

    expectInvalidFileToPreserveCache(name.replaceAll(" ", "-"), invalid);
  });

  it("atomically replaces an existing cache file", () => {
    pubkeyCache.save(tempPkixPath);
    const original = fs.readFileSync(tempPkixPath);

    seedCache(1);
    pubkeyCache.save(tempPkixPath);
    expect(fs.readFileSync(tempPkixPath)).not.toEqual(original);

    pubkeyCache.reset();
    pubkeyCache.load(tempPkixPath, pubkeyCache.capacity);
    expectCacheContents(1);

    seedCache();
  });

  it.runIf(canEnforceDirectoryPermissions)(
    "preserves an existing cache file when an atomic save cannot create its sibling file",
    () => {
      const readOnlyDir = path.join(tempDir, "read-only");
      const destination = path.join(readOnlyDir, "cache.pkix");
      fs.mkdirSync(readOnlyDir);

      pubkeyCache.save(destination);
      const original = fs.readFileSync(destination);
      seedCache(1);

      fs.chmodSync(readOnlyDir, 0o555);
      try {
        expect(() => pubkeyCache.save(destination)).toThrow();
      } finally {
        fs.chmodSync(readOnlyDir, 0o755);
      }

      expect(fs.readFileSync(destination)).toEqual(original);
      expect(fs.readdirSync(readOnlyDir)).toEqual(["cache.pkix"]);

      pubkeyCache.load(destination, pubkeyCache.capacity);
      expectCacheContents();
    }
  );

  it("reset clears both lookup directions", () => {
    const before = pubkeyCache.get(0);
    expect(before).toBeDefined();
    expect(pubkeyCache.getIndex(keypairs[0].pubkeyBytes)).toBeDefined();

    pubkeyCache.reset();

    expect(pubkeyCache.size).toBe(0);
    expect(pubkeyCache.get(0)).toBeUndefined();
    expect(pubkeyCache.getIndex(keypairs[0].pubkeyBytes)).toBeNull();
  });

  it("exposes native capacity", () => {
    expect(pubkeyCache.capacity).toBeGreaterThanOrEqual(2_000);
  });

  it("grows capacity after publishing entries without changing the cache", () => {
    seedCache();
    const capacityBefore = pubkeyCache.capacity;

    pubkeyCache.ensureCapacity(capacityBefore + 1);
    expect(pubkeyCache.capacity).toBeGreaterThanOrEqual(capacityBefore + 1);
    expectCacheContents();
  });

  it("rejects sparse inserts without changing the cache", () => {
    const sizeBefore = pubkeyCache.size;
    expect(() => pubkeyCache.set(pubkeyCache.capacity, keypairs[0].pubkeyBytes)).toThrow();
    expect(pubkeyCache.size).toBe(sizeBefore);
  });
});
