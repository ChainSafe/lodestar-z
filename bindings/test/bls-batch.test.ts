import {spawnSync} from "node:child_process";
import {unlinkSync, writeFileSync} from "node:fs";
import {join} from "node:path";
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

function makeIndexedSets(
  count: number,
  seedBase: number
): {index: number; message: Uint8Array; signature: Uint8Array}[] {
  return Array.from({length: count}, (_, i) => {
    const kp = keypairs[i % N];
    const message = makeMsg((seedBase + i) & 0xff);
    return {index: i % N, message, signature: kp.sk.sign(message).toBytes()};
  });
}

describe("blsBatch", () => {
  beforeAll(() => {
    pubkeyCache.ensureCapacity(N);
    for (let i = 0; i < N; i++) {
      pubkeyCache.set(i, keypairs[i].pubkeyBytes);
    }
    blsBatch.init(4);
  });

  // ── verify ────────────────────────────────────────────────

  describe("verify", () => {
    it("indexed: returns true for valid sets", () => {
      const sets = keypairs.map((kp, i) => ({
        index: i,
        message: makeMsg(10 + i),
        signature: kp.sk.sign(makeMsg(10 + i)).toBytes(),
      }));
      expect(blsBatch.verify(blsBatch.indexed, sets)).toBe(true);
    });

    it("indexed: returns false for an invalid set", () => {
      const sets = keypairs.map((kp, i) => ({
        index: i,
        message: makeMsg(10 + i),
        signature: kp.sk.sign(makeMsg(10 + i)).toBytes(),
      }));
      sets[0].signature = keypairs[1].sk.sign(makeMsg(99)).toBytes();
      expect(blsBatch.verify(blsBatch.indexed, sets)).toBe(false);
    });

    it("aggregate: returns true for valid sets", () => {
      const msg1 = makeMsg(20);
      const msg2 = makeMsg(21);
      const aggSig1 = aggregateSignatures([keypairs[0].sk.sign(msg1), keypairs[1].sk.sign(msg1)], false);
      const aggSig2 = aggregateSignatures([keypairs[2].sk.sign(msg2), keypairs[3].sk.sign(msg2)], false);
      expect(
        blsBatch.verify(blsBatch.aggregate, [
          {indices: [0, 1], message: msg1, signature: aggSig1.toBytes()},
          {indices: [2, 3], message: msg2, signature: aggSig2.toBytes()},
        ])
      ).toBe(true);
    });

    it("aggregate: returns false for wrong indices", () => {
      const msg = makeMsg(20);
      const aggSig = aggregateSignatures([keypairs[0].sk.sign(msg), keypairs[1].sk.sign(msg)], false);
      expect(blsBatch.verify(blsBatch.aggregate, [{indices: [0, 2], message: msg, signature: aggSig.toBytes()}])).toBe(
        false
      );
    });

    it("single: returns true for valid sets", () => {
      const sets = keypairs.map((kp, i) => ({
        message: makeMsg(30 + i),
        publicKey: kp.pubkeyBytes,
        signature: kp.sk.sign(makeMsg(30 + i)).toBytes(),
      }));
      expect(blsBatch.verify(blsBatch.single, sets)).toBe(true);
    });

    it("single: returns false for an invalid set", () => {
      const sets = keypairs.map((kp, i) => ({
        message: makeMsg(30 + i),
        publicKey: kp.pubkeyBytes,
        signature: kp.sk.sign(makeMsg(30 + i)).toBytes(),
      }));
      sets[0].signature = keypairs[1].sk.sign(makeMsg(99)).toBytes();
      expect(blsBatch.verify(blsBatch.single, sets)).toBe(false);
    });

    it("returns false for empty sets", () => {
      expect(blsBatch.verify(blsBatch.indexed, [])).toBe(false);
    });
  });

  // ── constants ─────────────────────────────────────────────

  describe("maxSetsPerJob", () => {
    it("is exported and matches the per-job cap (rejects one more)", () => {
      expect(blsBatch.maxSetsPerJob).toBeGreaterThan(0);
      const m = makeMsg(1);
      const tooMany = Array.from({length: blsBatch.maxSetsPerJob + 1}, (_, i) => ({
        index: i % N,
        message: m,
        signature: keypairs[i % N].sk.sign(m).toBytes(),
      }));
      expect(() => blsBatch.verify(blsBatch.indexed, tooMany)).toThrow();
    });
  });

  // ── asyncVerify ───────────────────────────────────────────

  describe("asyncVerify", () => {
    it("indexed: resolves true for valid sets", async () => {
      const sets = keypairs.map((kp, i) => ({
        index: i,
        message: makeMsg(40 + i),
        signature: kp.sk.sign(makeMsg(40 + i)).toBytes(),
      }));
      expect(await blsBatch.asyncVerify(blsBatch.indexed, sets)).toBe(true);
    });

    it("indexed: resolves false for an invalid set", async () => {
      const sets = keypairs.map((kp, i) => ({
        index: i,
        message: makeMsg(40 + i),
        signature: kp.sk.sign(makeMsg(40 + i)).toBytes(),
      }));
      sets[0].signature = keypairs[1].sk.sign(makeMsg(99)).toBytes();
      expect(await blsBatch.asyncVerify(blsBatch.indexed, sets)).toBe(false);
    });

    it("aggregate: resolves true for valid sets", async () => {
      const msg = makeMsg(50);
      const aggSig = aggregateSignatures(
        keypairs.map((kp) => kp.sk.sign(msg)),
        false
      );
      const result = await blsBatch.asyncVerify(blsBatch.aggregate, [
        {indices: [0, 1, 2, 3], message: msg, signature: aggSig.toBytes()},
      ]);
      expect(result).toBe(true);
    });

    it("aggregate: resolves false for an invalid set", async () => {
      const msg = makeMsg(50);
      const wrongSig = keypairs[0].sk.sign(makeMsg(99));
      const result = await blsBatch.asyncVerify(blsBatch.aggregate, [
        {indices: [0, 1, 2, 3], message: msg, signature: wrongSig.toBytes()},
      ]);
      expect(result).toBe(false);
    });

    it("single: resolves true for valid sets", async () => {
      const sets = keypairs.map((kp, i) => ({
        message: makeMsg(60 + i),
        publicKey: kp.pubkeyBytes,
        signature: kp.sk.sign(makeMsg(60 + i)).toBytes(),
      }));
      expect(await blsBatch.asyncVerify(blsBatch.single, sets)).toBe(true);
    });

    it("single: resolves false for an invalid set", async () => {
      const sets = keypairs.map((kp, i) => ({
        message: makeMsg(60 + i),
        publicKey: kp.pubkeyBytes,
        signature: kp.sk.sign(makeMsg(60 + i)).toBytes(),
      }));
      sets[0].signature = keypairs[1].sk.sign(makeMsg(99)).toBytes();
      expect(await blsBatch.asyncVerify(blsBatch.single, sets)).toBe(false);
    });

    it("resolves false for empty sets", async () => {
      expect(await blsBatch.asyncVerify(blsBatch.indexed, [])).toBe(false);
    });
  });

  // ── asyncVerifySameMessage ────────────────────────────────

  describe("asyncVerifySameMessage", () => {
    it("resolves true for valid sets", async () => {
      const message = makeMsg(70);
      const sets = keypairs.map((kp, i) => ({
        index: i,
        signature: kp.sk.sign(message).toBytes(),
      }));
      expect(await blsBatch.asyncVerifySameMessage(sets, message)).toBe(true);
    });

    it("resolves false for a wrong signature", async () => {
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

  // ── error handling for invalid inputs ────────────────────────

  describe("error handling for invalid inputs", () => {
    it("asyncVerify throws for an invalid signature (bad bytes)", () => {
      expect(() =>
        blsBatch.asyncVerify(blsBatch.single, [
          {
            message: makeMsg(80),
            publicKey: keypairs[0].pubkeyBytes,
            signature: new Uint8Array(96), // all zeros — fails deserialization
          },
        ])
      ).toThrow();
    });

    it("thrown error is an Error instance with .code", () => {
      try {
        blsBatch.asyncVerify(blsBatch.single, [
          {
            message: makeMsg(81),
            publicKey: keypairs[0].pubkeyBytes,
            signature: new Uint8Array(96),
          },
        ]);
        expect.unreachable("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(Error);
        expect((err as Error & {code: string}).code).toBe("DeserializationFailed");
      }
    });

    it("asyncVerify throws for an out-of-range pubkey index", () => {
      const msg = makeMsg(82);
      try {
        blsBatch.asyncVerify(blsBatch.indexed, [
          {
            index: 99999,
            message: msg,
            signature: keypairs[0].sk.sign(msg).toBytes(),
          },
        ]);
        expect.unreachable("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(Error);
        expect((err as Error & {code: string}).code).toBe("PubkeyIndexOutOfRange");
      }
    });
  });

  // ── worker pool: concurrency, backpressure, idempotency ───────
  describe("worker pool", () => {
    it("handles repeated concurrent batches without leaking slots", async () => {
      for (let round = 0; round < 50; round++) {
        const jobs = Array.from({length: 4}, (_, i) => {
          const m = makeMsg(((round + i) % 200) + 1);
          return blsBatch.asyncVerify(blsBatch.indexed, [
            {index: i, message: m, signature: keypairs[i].sk.sign(m).toBytes()},
          ]);
        });
        expect((await Promise.all(jobs)).every((r) => r)).toBe(true);
      }
    });

    it("throws PoolExhausted when all slots are in flight", async () => {
      const inflight: Promise<boolean>[] = [];
      let code: string | undefined;
      try {
        for (let i = 0; i < 5; i++) {
          const m = makeMsg(150 + i);
          inflight.push(
            blsBatch.asyncVerify(blsBatch.indexed, [
              {index: i % N, message: m, signature: keypairs[i % N].sk.sign(m).toBytes()},
            ])
          );
        }
      } catch (e) {
        code = (e as Error & {code?: string}).code;
      }
      await Promise.allSettled(inflight);
      expect(code).toBe("PoolExhausted");
    });

    it("reports native backpressure while all slots are reserved", async () => {
      const inflight: Promise<boolean>[] = [];
      try {
        expect(blsBatch.canAcceptWork()).toBe(true);

        for (let i = 0; i < 4; i++) {
          inflight.push(blsBatch.asyncVerify(blsBatch.indexed, makeIndexedSets(blsBatch.maxSetsPerJob, 180 + i)));
        }

        expect(blsBatch.canAcceptWork()).toBe(false);
      } finally {
        await Promise.allSettled(inflight);
      }

      expect(blsBatch.canAcceptWork()).toBe(true);
    });

    it("stats() reports real pool occupancy", async () => {
      const idle = blsBatch.stats();
      expect(idle.initialized).toBe(true);
      expect(idle.maxInflight).toBe(4);
      expect(idle.freeSlots).toBe(4);
      expect(idle.workers).toBeGreaterThan(0);
      expect(idle.active).toBe(0);
      expect(idle.queued).toBe(0);
      expect(idle.running).toBe(0);

      const inflight: Promise<boolean>[] = [];
      try {
        for (let i = 0; i < 4; i++) {
          inflight.push(blsBatch.asyncVerify(blsBatch.indexed, makeIndexedSets(blsBatch.maxSetsPerJob, 190 + i)));
        }
        // Synchronous: no completion can run before we await, so all 4 slots are reserved.
        const busy = blsBatch.stats();
        expect(busy.active).toBe(4);
        expect(busy.freeSlots).toBe(0);
        expect(busy.queued + busy.running).toBeLessThanOrEqual(4);
        expect(busy.running).toBeLessThanOrEqual(busy.workers);
      } finally {
        await Promise.allSettled(inflight);
      }

      const drained = blsBatch.stats();
      expect(drained.active).toBe(0);
      expect(drained.freeSlots).toBe(4);
      expect(drained.queued).toBe(0);
      expect(drained.running).toBe(0);

      // Every completed async job observes a queue-residency sample.
      expect(drained.queueWait.count).toBeGreaterThan(0);
      expect(drained.queueWait.bounds).toEqual([0.01, 0.02, 0.1, 0.3, 0.5, 1]);
      expect(drained.queueWait.counts).toHaveLength(drained.queueWait.bounds.length);
      // Cumulative buckets are non-decreasing and bounded by the total count.
      for (const c of drained.queueWait.counts) expect(c).toBeLessThanOrEqual(drained.queueWait.count);
    });

    it("init is idempotent", () => {
      expect(() => blsBatch.init(4)).not.toThrow();
      const m = makeMsg(9);
      expect(
        blsBatch.verify(blsBatch.single, [
          {message: m, publicKey: keypairs[0].pubkeyBytes, signature: keypairs[0].sk.sign(m).toBytes()},
        ])
      ).toBe(true);
    });
  });

  // ── shutdown: clean exit with async work in flight (UAF regression) ──
  describe("shutdown", () => {
    it("exits cleanly with async work in flight", () => {
      const projectRoot = join(import.meta.dirname, "../..");
      const fixturePath = join(projectRoot, `bindings/test/.tmp-bls-shutdown-${process.pid}.mjs`);
      writeFileSync(
        fixturePath,
        `
import {blsBatch} from "../src/bls-batch.js";
import {SecretKey} from "../src/blst.js";
import {pubkeyCache} from "../src/pubkeys.js";
const N = 128;
const kps = Array.from({length: N}, (_, i) => { const ikm = new Uint8Array(32); ikm[0]=(i%255)+1; ikm[1]=(i>>8)+1; const sk=SecretKey.fromKeygen(ikm); return {sk, pk: sk.toPublicKey().toBytes()}; });
pubkeyCache.ensureCapacity(N);
for (let i=0;i<N;i++) pubkeyCache.set(i, kps[i].pk);
blsBatch.init(8);
const msg = new Uint8Array(32); msg[0]=7;
// Heavy batches left in flight at exit: worker_pool.deinit must join workers
// (and release the TSFN) before the slot buffers they read are freed.
for (let j=0;j<4;j++) {
  const sets = kps.map((kp,i)=>({index:i, message:msg, signature:kp.sk.sign(msg).toBytes()}));
  blsBatch.asyncVerify(blsBatch.indexed, sets).then(()=>{},()=>{});
}
console.log("submitted");
`
      );
      try {
        // The UAF was intermittent; run several times.
        for (let run = 0; run < 5; run++) {
          const result = spawnSync(process.execPath, [fixturePath], {
            cwd: projectRoot,
            encoding: "utf-8",
            timeout: 30_000,
          });
          expect(result.status, `run ${run} signal=${result.signal} stderr=${result.stderr}`).toBe(0);
          expect(result.stderr ?? "", "no segfault/panic").not.toMatch(/panic:|Segmentation/);
        }
      } finally {
        try {
          unlinkSync(fixturePath);
        } catch (_e) {
          // ignore
        }
      }
    }, 90_000);

    it("releases the blsBatch owner env when a worker-thread importer exits", () => {
      const projectRoot = join(import.meta.dirname, "../..");
      const workerPath = join(projectRoot, `bindings/test/.tmp-bls-env-worker-${process.pid}.mjs`);
      const mainPath = join(projectRoot, `bindings/test/.tmp-bls-env-main-${process.pid}.mjs`);

      writeFileSync(
        workerPath,
        `
import {parentPort} from "node:worker_threads";
import {blsBatch} from "../src/bls-batch.js";
import {SecretKey} from "../src/blst.js";
import {pubkeyCache} from "../src/pubkeys.js";

const ikm = new Uint8Array(32);
ikm[0] = 31;
const sk = SecretKey.fromKeygen(ikm);
const pk = sk.toPublicKey().toBytes();
pubkeyCache.ensureCapacity(1);
pubkeyCache.set(0, pk);
blsBatch.init(2);

const message = new Uint8Array(32);
message[0] = 17;
const ok = await blsBatch.asyncVerify(blsBatch.indexed, [
  {index: 0, message, signature: sk.sign(message).toBytes()},
]);
parentPort.postMessage(ok ? "worker-ok" : "worker-bad");
`
      );

      writeFileSync(
        mainPath,
        `
import {Worker} from "node:worker_threads";
import {blsBatch} from "../src/bls-batch.js";
import {SecretKey} from "../src/blst.js";
import {pubkeyCache} from "../src/pubkeys.js";

const worker = new Worker(${JSON.stringify(workerPath)}, {type: "module"});
await new Promise((resolve, reject) => {
  let ok = false;
  worker.on("message", (msg) => {
    if (msg === "worker-ok") ok = true;
    else reject(new Error(String(msg)));
  });
  worker.on("error", reject);
  worker.on("exit", (code) => {
    if (code === 0 && ok) resolve(undefined);
    else reject(new Error(\`worker exit \${code}, ok=\${ok}\`));
  });
});

const ikm = new Uint8Array(32);
ikm[0] = 32;
const sk = SecretKey.fromKeygen(ikm);
const pk = sk.toPublicKey().toBytes();
pubkeyCache.ensureCapacity(1);
pubkeyCache.set(0, pk);
blsBatch.init(2);

const message = new Uint8Array(32);
message[0] = 18;
const ok = await blsBatch.asyncVerify(blsBatch.indexed, [
  {index: 0, message, signature: sk.sign(message).toBytes()},
]);
if (!ok) throw new Error("main blsBatch owner env was not restored");
`
      );

      try {
        const result = spawnSync(process.execPath, [mainPath], {
          cwd: projectRoot,
          encoding: "utf-8",
          timeout: 30_000,
        });
        expect(result.status, `signal=${result.signal} stdout=${result.stdout} stderr=${result.stderr}`).toBe(0);
      } finally {
        for (const path of [workerPath, mainPath]) {
          try {
            unlinkSync(path);
          } catch (_e) {
            // ignore
          }
        }
      }
    }, 45_000);
  });
});
