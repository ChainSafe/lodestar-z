import {spawnSync} from "node:child_process";
import {existsSync, mkdtempSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join} from "node:path";
import {expect, test} from "vitest";

const headers = join(dirname(process.execPath), "..", "include", "node");
/** Past the 47-bit user address space, so the allocation fails whatever the overcommit policy. */
const unallocatable = 2 ** 48;

function run(script: string) {
  return spawnSync(process.execPath, ["-e", script], {encoding: "utf8", timeout: 60000});
}

// Pins the exchange's failure classification: a payload ArrayBuffer that N-API cannot allocate returns no status,
// so no N-API outcome of a payload buffer creation is an operation-local allocation failure. Only the network
// allocator's OutOfMemory is.
test.skipIf(!existsSync(join(headers, "node_api.h")))(
  "an N-API ArrayBuffer allocation failure terminates the process instead of returning a status",
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
  },
  60000
);
