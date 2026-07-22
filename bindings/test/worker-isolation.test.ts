import {spawnSync} from "node:child_process";
import crypto from "node:crypto";
import {Worker} from "node:worker_threads";
import {describe, expect, it} from "vitest";
import {PublicKey, SecretKey, Signature, verify} from "../src/blst.js";

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

  it("does not transfer cache administration after the control environment exits", () => {
    const ownerSource = `
      import {parentPort, workerData} from "node:worker_threads";
      import {pubkeyCache} from ${JSON.stringify(pubkeysModulePath)};
      import {SecretKey} from ${JSON.stringify(blstModulePath)};

      const barrier = new Int32Array(workerData.barrierBuffer);
      try {
        const ikm = new Uint8Array(32);
        ikm[0] = 1;
        const pubkey = SecretKey.fromKeygen(ikm).toPublicKey().toBytes();
        pubkeyCache.ensureCapacity(8);
        pubkeyCache.set(0, pubkey);
        pubkeyCache.save(workerData.snapshotPath);
        Atomics.store(barrier, 0, 1);
        Atomics.notify(barrier, 0);
        while (Atomics.load(barrier, 2) === 0) Atomics.wait(barrier, 2, 0);
        parentPort.postMessage({ok: true});
      } catch (error) {
        Atomics.store(barrier, 0, -1);
        Atomics.notify(barrier, 0);
        parentPort.postMessage({fatal: String(error?.stack ?? error)});
      }
    `;
    const successorSource = `
      import {parentPort, workerData} from "node:worker_threads";
      import {pubkeyCache} from ${JSON.stringify(pubkeysModulePath)};

      const barrier = new Int32Array(workerData.barrierBuffer);

      function capture(operation) {
        try {
          operation();
          return null;
        } catch (error) {
          return String(error?.message ?? error);
        }
      }

      try {
        if (pubkeyCache.size !== 1) throw new Error("successor could not read the shared cache");
        const saveBeforeOwnerExit = capture(() => pubkeyCache.save(workerData.successorPath));
        Atomics.store(barrier, 1, 1);
        Atomics.notify(barrier, 1);
        while (Atomics.load(barrier, 3) === 0) Atomics.wait(barrier, 3, 0);

        parentPort.postMessage({
          cacheSize: pubkeyCache.size,
          saveBeforeOwnerExit,
          saveAfterOwnerExit: capture(() => pubkeyCache.save(workerData.successorPath)),
          loadAfterOwnerExit: capture(() => pubkeyCache.load(workerData.snapshotPath, 8)),
          resetAfterOwnerExit: capture(() => pubkeyCache.reset()),
        });
      } catch (error) {
        Atomics.store(barrier, 1, -1);
        Atomics.notify(barrier, 1);
        parentPort.postMessage({fatal: String(error?.stack ?? error)});
      }
    `;
    const childSource = `
      import fs from "node:fs";
      import os from "node:os";
      import path from "node:path";
      import {Worker} from "node:worker_threads";

      const ownerSource = ${JSON.stringify(ownerSource)};
      const successorSource = ${JSON.stringify(successorSource)};

      function runWorker(source, workerData) {
        return new Promise((resolve, reject) => {
          let message;
          const worker = new Worker(source, {eval: true, workerData});
          worker.on("message", (value) => { message = value; });
          worker.on("error", reject);
          worker.on("exit", (code) => {
            if (code !== 0) return reject(new Error("worker exited with code " + code));
            if (message === undefined) return reject(new Error("worker produced no result"));
            resolve(message);
          });
        });
      }

      function waitUntilReady(barrier, index, name) {
        const deadline = Date.now() + 10_000;
        while (Atomics.load(barrier, index) === 0) {
          if (Date.now() >= deadline) throw new Error("timed out waiting for " + name);
          Atomics.wait(barrier, index, 0, 100);
        }
        if (Atomics.load(barrier, index) < 0) throw new Error(name + " failed before becoming ready");
      }

      function expectError(actual, expected, operation) {
        if (actual !== expected) {
          throw new Error(operation + " returned " + JSON.stringify(actual) + ", expected " + expected);
        }
      }

      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "lodestar-z-owner-exit-"));
      const snapshotPath = path.join(tempDir, "snapshot.pkix");
      const successorPath = path.join(tempDir, "successor.pkix");
      const barrierBuffer = new SharedArrayBuffer(4 * Int32Array.BYTES_PER_ELEMENT);
      const barrier = new Int32Array(barrierBuffer);

      try {
        const owner = runWorker(ownerSource, {barrierBuffer, snapshotPath});
        waitUntilReady(barrier, 0, "owner");

        const successor = runWorker(successorSource, {barrierBuffer, snapshotPath, successorPath});
        waitUntilReady(barrier, 1, "successor");

        Atomics.store(barrier, 2, 1);
        Atomics.notify(barrier, 2);
        const ownerResult = await owner;
        if (ownerResult.fatal !== undefined) throw new Error(ownerResult.fatal);

        Atomics.store(barrier, 3, 1);
        Atomics.notify(barrier, 3);
        const successorResult = await successor;
        if (successorResult.fatal !== undefined) throw new Error(successorResult.fatal);
        if (successorResult.cacheSize !== 1) throw new Error("cache changed after owner exit");
        expectError(successorResult.saveBeforeOwnerExit, "PubkeyCacheControlEnvironmentOnly", "successor save before owner exit");
        expectError(successorResult.saveAfterOwnerExit, "PubkeyCacheControlEnvironmentOnly", "successor save after owner exit");
        expectError(successorResult.loadAfterOwnerExit, "PubkeyCacheControlEnvironmentOnly", "successor load after owner exit");
        expectError(successorResult.resetAfterOwnerExit, "PubkeyCacheControlEnvironmentOnly", "successor reset after owner exit");
        if (fs.existsSync(successorPath)) throw new Error("successor save created a file");
      } finally {
        Atomics.store(barrier, 2, 1);
        Atomics.notify(barrier, 2);
        Atomics.store(barrier, 3, 1);
        Atomics.notify(barrier, 3);
        fs.rmSync(tempDir, {force: true, recursive: true});
      }
    `;

    expectChildSuccess(childSource);
  }, 30_000);
});

const pubkeysModulePath = new URL("../src/pubkeys.js", import.meta.url).href;
const blstModulePath = new URL("../src/blst.js", import.meta.url).href;

function expectChildSuccess(source: string): void {
  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", source], {
    cwd: new URL("../..", import.meta.url),
    encoding: "utf-8",
    timeout: 20_000,
  });
  const diagnostics = `error=${result.error?.stack ?? "none"} stdout=${result.stdout} stderr=${result.stderr}`;
  expect(result.status, diagnostics).toBe(0);
}

function runWorker(): Promise<string> {
  return new Promise((resolve, reject) => {
    let received = false;
    let result: string;
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

    worker.on("message", (message: string) => {
      received = true;
      result = message;
    });
    worker.on("error", reject);
    worker.on("exit", (code) => {
      if (code !== 0) {
        reject(new Error(`Worker exited with code ${code}`));
      } else if (!received) {
        reject(new Error("Worker exited without a result"));
      } else {
        resolve(result);
      }
    });
  });
}
