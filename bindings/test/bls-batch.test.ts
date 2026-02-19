import {beforeAll, describe, expect, it} from "vitest";
import {blsBatch} from "../src/bls-batch.js";
import {SecretKey, aggregateSignatures} from "../src/blst.js";
import {pubkeyCache} from "../src/pubkeys.js";

const N = 4;
const keypairs = Array.from({length: N}, (_, i) => {
  const ikm = new Uint8Array(32);
  ikm[0] = i + 1;
  const sk = SecretKey.fromKeygen(ikm);
  const pk = sk.toPublicKey();
  return {pk, pubkeyBytes: pk.toBytes(), sk};
});

function makeMsg(seed: number): Uint8Array {
  const msg = new Uint8Array(32);
  msg[0] = seed;
  return msg;
}

describe("blsBatch", () => {
  beforeAll(() => {
    pubkeyCache.ensureCapacity(N);
    for (let i = 0; i < N; i++) {
      pubkeyCache.set(i, keypairs[i].pubkeyBytes);
    }
  });

  // ── verifyIndexed ──────────────────────────────────────────

  describe("verifyIndexed", () => {
    it("returns true for valid sets", () => {
      const sets = keypairs.map((kp, i) => ({
        index: i,
        message: makeMsg(10 + i),
        signature: kp.sk.sign(makeMsg(10 + i)).toBytes(),
      }));
      expect(blsBatch.verifyIndexed(sets)).toBe(true);
    });

    it("returns false when a set is invalid", () => {
      const sets = keypairs.map((kp, i) => ({
        index: i,
        message: makeMsg(10 + i),
        signature: kp.sk.sign(makeMsg(10 + i)).toBytes(),
      }));
      sets[0].signature = keypairs[1].sk.sign(makeMsg(99)).toBytes();
      expect(blsBatch.verifyIndexed(sets)).toBe(false);
    });

    it("returns false for empty sets", () => {
      expect(blsBatch.verifyIndexed([])).toBe(false);
    });
  });

  // ── verifyAggregate ────────────────────────────────────────

  describe("verifyAggregate", () => {
    it("returns true for valid aggregate sets", () => {
      const msg1 = makeMsg(20);
      const msg2 = makeMsg(21);
      const aggSig1 = aggregateSignatures([keypairs[0].sk.sign(msg1), keypairs[1].sk.sign(msg1)], false);
      const aggSig2 = aggregateSignatures([keypairs[2].sk.sign(msg2), keypairs[3].sk.sign(msg2)], false);
      expect(
        blsBatch.verifyAggregate([
          {indices: [0, 1], message: msg1, signature: aggSig1.toBytes()},
          {indices: [2, 3], message: msg2, signature: aggSig2.toBytes()},
        ])
      ).toBe(true);
    });

    it("returns false when indices are wrong", () => {
      const msg = makeMsg(20);
      const aggSig = aggregateSignatures([keypairs[0].sk.sign(msg), keypairs[1].sk.sign(msg)], false);
      // wrong indices: 0,2 instead of 0,1
      expect(blsBatch.verifyAggregate([{indices: [0, 2], message: msg, signature: aggSig.toBytes()}])).toBe(false);
    });

    it("returns false for empty sets", () => {
      expect(blsBatch.verifyAggregate([])).toBe(false);
    });
  });

  // ── verifySingle ───────────────────────────────────────────

  describe("verifySingle", () => {
    it("returns true for valid sets", () => {
      const sets = keypairs.map((kp, i) => ({
        message: makeMsg(30 + i),
        publicKey: kp.pubkeyBytes,
        signature: kp.sk.sign(makeMsg(30 + i)).toBytes(),
      }));
      expect(blsBatch.verifySingle(sets)).toBe(true);
    });

    it("returns false when a set is invalid", () => {
      const sets = keypairs.map((kp, i) => ({
        message: makeMsg(30 + i),
        publicKey: kp.pubkeyBytes,
        signature: kp.sk.sign(makeMsg(30 + i)).toBytes(),
      }));
      sets[0].signature = keypairs[1].sk.sign(makeMsg(99)).toBytes();
      expect(blsBatch.verifySingle(sets)).toBe(false);
    });

    it("returns false for empty sets", () => {
      expect(blsBatch.verifySingle([])).toBe(false);
    });
  });

  // ── asyncVerifyIndexed ─────────────────────────────────────

  describe("asyncVerifyIndexed", () => {
    it("resolves true for valid sets", async () => {
      const sets = keypairs.map((kp, i) => ({
        index: i,
        message: makeMsg(40 + i),
        signature: kp.sk.sign(makeMsg(40 + i)).toBytes(),
      }));
      expect(await blsBatch.asyncVerifyIndexed(sets)).toBe(true);
    });

    it("resolves false when a set is invalid", async () => {
      const sets = keypairs.map((kp, i) => ({
        index: i,
        message: makeMsg(40 + i),
        signature: kp.sk.sign(makeMsg(40 + i)).toBytes(),
      }));
      sets[0].signature = keypairs[1].sk.sign(makeMsg(99)).toBytes();
      expect(await blsBatch.asyncVerifyIndexed(sets)).toBe(false);
    });

    it("resolves false for empty sets", async () => {
      expect(await blsBatch.asyncVerifyIndexed([])).toBe(false);
    });
  });

  // ── asyncVerifyAggregate ───────────────────────────────────

  describe("asyncVerifyAggregate", () => {
    it("resolves true for valid sets", async () => {
      const msg = makeMsg(50);
      const aggSig = aggregateSignatures(
        keypairs.map((kp) => kp.sk.sign(msg)),
        false
      );
      const result = await blsBatch.asyncVerifyAggregate([
        {indices: [0, 1, 2, 3], message: msg, signature: aggSig.toBytes()},
      ]);
      expect(result).toBe(true);
    });

    it("resolves false when a set is invalid", async () => {
      const msg = makeMsg(50);
      const wrongSig = keypairs[0].sk.sign(makeMsg(99));
      const result = await blsBatch.asyncVerifyAggregate([
        {indices: [0, 1, 2, 3], message: msg, signature: wrongSig.toBytes()},
      ]);
      expect(result).toBe(false);
    });

    it("resolves false for empty sets", async () => {
      expect(await blsBatch.asyncVerifyAggregate([])).toBe(false);
    });
  });

  // ── asyncVerifySingle ──────────────────────────────────────

  describe("asyncVerifySingle", () => {
    it("resolves true for valid sets", async () => {
      const sets = keypairs.map((kp, i) => ({
        message: makeMsg(60 + i),
        publicKey: kp.pubkeyBytes,
        signature: kp.sk.sign(makeMsg(60 + i)).toBytes(),
      }));
      expect(await blsBatch.asyncVerifySingle(sets)).toBe(true);
    });

    it("resolves false when a set is invalid", async () => {
      const sets = keypairs.map((kp, i) => ({
        message: makeMsg(60 + i),
        publicKey: kp.pubkeyBytes,
        signature: kp.sk.sign(makeMsg(60 + i)).toBytes(),
      }));
      sets[0].signature = keypairs[1].sk.sign(makeMsg(99)).toBytes();
      expect(await blsBatch.asyncVerifySingle(sets)).toBe(false);
    });

    it("resolves false for empty sets", async () => {
      expect(await blsBatch.asyncVerifySingle([])).toBe(false);
    });
  });

  // ── asyncVerifySameMessage ─────────────────────────────────

  describe("asyncVerifySameMessage", () => {
    it("resolves true for valid same-message sets", async () => {
      const message = makeMsg(70);
      const sets = keypairs.map((kp, i) => ({
        index: i,
        signature: kp.sk.sign(message).toBytes(),
      }));
      expect(await blsBatch.asyncVerifySameMessage(sets, message)).toBe(true);
    });

    it("resolves false when a signature is wrong", async () => {
      const message = makeMsg(70);
      const sets = keypairs.map((kp, i) => ({
        index: i,
        signature: kp.sk.sign(message).toBytes(),
      }));
      sets[0].signature = keypairs[1].sk.sign(makeMsg(99)).toBytes();
      expect(await blsBatch.asyncVerifySameMessage(sets, message)).toBe(false);
    });

    it("resolves false for empty sets", async () => {
      expect(await blsBatch.asyncVerifySameMessage([], makeMsg(70))).toBe(false);
    });
  });
});
