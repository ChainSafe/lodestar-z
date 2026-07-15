import crypto from "node:crypto";
import {Worker} from "node:worker_threads";
import {describe, expect, it} from "vitest";
import {PublicKey, SecretKey, Signature, verify} from "../src/blst.js";
import {pubkeyCache} from "../src/pubkeys.js";

/**
 * Tests that the per-context instance data (blst InstanceData) and
 * refcounted shared state (pool, pubkeys, config) survive a worker
 * thread loading and unloading the bindings.
 *
 * Before the cleanup-hook + refcount refactor, a worker's env teardown
 * would have wiped shared module globals, corrupting the main thread.
 */
describe("worker isolation", () => {
  it("main thread blst operations survive a worker loading and unloading bindings", async () => {
    // 1. Do blst work on the main thread before the worker
    const sk = SecretKey.fromKeygen(crypto.randomBytes(32));
    const pk = sk.toPublicKey();
    const msg = crypto.randomBytes(32);
    const sig = sk.sign(msg);
    expect(verify(msg, pk, sig)).toBe(true);

    // 2. Spawn a worker that loads bindings, does blst work, then exits
    const workerResult = await runWorker();
    expect(workerResult).toBe("ok");

    // 3. After the worker's env teardown + cleanup hooks have fired,
    //    verify main thread blst operations still work
    const sk2 = SecretKey.fromKeygen(crypto.randomBytes(32));
    const pk2 = sk2.toPublicKey();
    const msg2 = crypto.randomBytes(32);
    const sig2 = sk2.sign(msg2);
    expect(verify(msg2, pk2, sig2)).toBe(true);

    // Original keys should still work too
    expect(verify(msg, pk, sig)).toBe(true);
    expect(pk).toBeInstanceOf(PublicKey);
    expect(sig).toBeInstanceOf(Signature);
  });

  it("multiple sequential workers do not corrupt state", async () => {
    const sk = SecretKey.fromKeygen(crypto.randomBytes(32));
    const pk = sk.toPublicKey();
    const msg = crypto.randomBytes(32);
    const sig = sk.sign(msg);

    for (let i = 0; i < 3; i++) {
      const result = await runWorker();
      expect(result).toBe("ok");

      // Main thread still works after each worker teardown
      expect(verify(msg, pk, sig)).toBe(true);
    }
  });

  it("shares the singleton cache safely while a worker reads and the main thread grows it", async () => {
    pubkeyCache.reset();
    pubkeyCache.ensureCapacity(1);
    const pubkeyBytes = SecretKey.fromKeygen(crypto.randomBytes(32)).toPublicKey().toBytes();
    pubkeyCache.set(0, pubkeyBytes);

    const coordination = new SharedArrayBuffer(2 * Int32Array.BYTES_PER_ELEMENT);
    const reader = new Worker(
      `
      import {parentPort, workerData} from "node:worker_threads";
      import {pubkeyCache} from "${new URL("../src/pubkeys.js", import.meta.url).href}";

      parentPort.postMessage({ready: true, size: pubkeyCache.size});
      const coordination = new Int32Array(workerData.coordination);
      Atomics.wait(coordination, 0, 0);

      for (let i = 0; i < 2_000; i++) {
        if (pubkeyCache.get(0) === undefined) throw new Error("shared key disappeared");
        pubkeyCache.aggregate([0, 0, 0, 0]);
      }
      Atomics.wait(coordination, 1, 0);
      parentPort.postMessage({done: true, size: pubkeyCache.size});
      `,
      {eval: true, workerData: {coordination}}
    );
    const exited = workerExit(reader);

    const ready = await nextWorkerMessage(reader);
    expect(ready).toEqual({ready: true, size: 1});
    const doneMessage = nextWorkerMessage(reader);
    const coordinationView = new Int32Array(coordination);
    Atomics.store(coordinationView, 0, 1);
    Atomics.notify(coordinationView, 0);

    for (let index = 1; index <= 5_000; index++) {
      pubkeyCache.set(index, pubkeyBytes);
    }
    Atomics.store(coordinationView, 1, 1);
    Atomics.notify(coordinationView, 1);

    const done = await doneMessage;
    expect(done).toEqual({done: true, size: 5_001});
    await exited;
  }, 30_000);
});

const blstModulePath = new URL("../src/blst.js", import.meta.url).href;

function nextWorkerMessage(worker: Worker): Promise<unknown> {
  return new Promise((resolve, reject) => {
    worker.once("message", resolve);
    worker.once("error", reject);
  });
}

function workerExit(worker: Worker): Promise<void> {
  return new Promise((resolve, reject) => {
    worker.once("exit", (code) => (code === 0 ? resolve() : reject(new Error(`Worker exited with code ${code}`))));
    worker.once("error", reject);
  });
}

function runWorker(): Promise<string> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(
      `
      import crypto from "node:crypto";
      import {parentPort} from "node:worker_threads";
      import {SecretKey, verify} from "${blstModulePath}";

      try {
        const sk = SecretKey.fromKeygen(crypto.randomBytes(32));
        const pk = sk.toPublicKey();
        const msg = crypto.randomBytes(32);
        const sig = sk.sign(msg);

        if (!verify(msg, pk, sig)) {
          parentPort.postMessage("verify failed in worker");
        } else {
          parentPort.postMessage("ok");
        }
      } catch (e) {
        parentPort.postMessage("error: " + e.message);
      }
      `,
      {eval: true}
    );

    worker.on("message", resolve);
    worker.on("error", reject);
    worker.on("exit", (code) => {
      if (code !== 0) reject(new Error(`Worker exited with code ${code}`));
    });
  });
}
