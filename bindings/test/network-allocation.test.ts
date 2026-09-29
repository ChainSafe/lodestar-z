import {spawnSync} from "node:child_process";
import {existsSync, mkdtempSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join} from "node:path";
import {expect, test} from "vitest";
import {childTestTimeout, spawnChild} from "./utils/network.js";

const headers = join(dirname(process.execPath), "..", "include", "node");
/** Past the 47-bit user address space, so the allocation fails whatever the overcommit policy. */
const unallocatable = 2 ** 48;

function run(script: string) {
  return spawnChild(["-e", script]);
}

// Pins the exchange's failure classification: a payload ArrayBuffer that N-API cannot allocate returns no status,
// so no N-API outcome of a payload buffer creation is an operation-local allocation failure. Only the network
// allocator's OutOfMemory is.
test.skipIf(!existsSync(join(headers, "node_api.h")))(
  "an N-API ArrayBuffer allocation failure terminates the process instead of returning a status",
  childTestTimeout(3, 30000),
  () => {
    const directory = mkdtempSync(join(tmpdir(), "lodestar-z-arraybuffer-"));
    try {
      const addon = join(directory, "probe.node");
      const source = join(import.meta.dirname, "fixtures", "network-arraybuffer-probe.c");
      const built = spawnSync("zig", ["cc", "-shared", "-fPIC", "-O2", "-I", headers, "-o", addon, source], {
        encoding: "utf8",
      });
      expect(built.status, built.stderr).toBe(0);
      const native = run(`console.log(JSON.stringify(require(${JSON.stringify(addon)}).create(${unallocatable})))`);
      expect(native.stdout).toBe("");
      expect(native.signal).toBe("SIGABRT");
      expect(native.stderr).toContain("FATAL ERROR: v8::ArrayBuffer::New Allocation failed - process out of memory");
      // The same failure in JavaScript is a catchable RangeError, so a RangeError alone never means allocation.
      const script = run(
        `try { new ArrayBuffer(${unallocatable}) } catch (e) { console.log(e.name + ": " + e.message) }`
      );
      expect(script.stdout.trim()).toBe("RangeError: Array buffer allocation failed");
      expect(run(`console.log(require(${JSON.stringify(addon)}).create(16).status)`).stdout.trim()).toBe("0");
    } finally {
      rmSync(directory, {force: true, recursive: true});
    }
  }
);

/** A publication payload length nothing else in the process allocates. */
const refusedBytes = 654321;
/** The fault shim forwards every other allocation to glibc. */
const glibc = Boolean(
  (process.report.getReport() as {header?: {glibcVersionRuntime?: string}}).header?.glibcVersionRuntime
);

// The network allocator's OutOfMemory is operation-local: it refuses that publication alone, and the network stays
// running until a requested close.
test.skipIf(!glibc)(
  "a publication whose payload copy cannot be allocated rejects alone and never escalates",
  childTestTimeout(1, 30000),
  () => {
    const directory = mkdtempSync(join(tmpdir(), "lodestar-z-malloc-"));
    try {
      const shim = join(directory, "fault.so");
      const source = join(import.meta.dirname, "fixtures", "network-malloc-fault.c");
      const built = spawnSync("zig", ["cc", "-shared", "-fPIC", "-O2", "-o", shim, source], {encoding: "utf8"});
      expect(built.status, built.stderr).toBe(0);
      const script = `import {createNativeNetwork} from "./bindings/src/network.js";
        import {applicationConfig, topicName} from "./bindings/test/utils/network.ts";
        const host = {
          capacity: () => ({ordinary: true, serving: 32}),
          validate: (job) => Promise.resolve(job.messages.map(() => "ignore")),
          checkDependencies: (checks) => checks.map(() => false),
          serve: (request) => request.cancel(),
          peers: () => undefined,
          failed: () => undefined,
          logs: () => undefined,
        };
        const network = createNativeNetwork(applicationConfig(), host);
        const publish = (bytes) => network.publish(topicName(), new Uint8Array(bytes), {allowZeroPeers: true});
        const refused = await publish(${refusedBytes}).then(() => "published", (error) => error.code);
        const admitted = await publish(${refusedBytes + 1});
        console.log(JSON.stringify({admitted, closed: await network.close(), refused}));`;
      const child = spawnChild(["--import", "tsx", "--input-type=module", "-e", script], {
        ...process.env,
        LD_PRELOAD: shim,
        NETWORK_MALLOC_FAULT_BYTES: String(refusedBytes),
      });
      expect(child.status, child.stderr).toBe(0);
      expect(JSON.parse(child.stdout)).toEqual({
        admitted: {duplicate: false, pressured: 0, queued: 0, selected: 0, unavailable: 0},
        closed: {reason: "requested"},
        refused: "OutOfMemory",
      });
    } finally {
      rmSync(directory, {force: true, recursive: true});
    }
  }
);
