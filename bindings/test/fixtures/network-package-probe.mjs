// Run from a consumer that installed the packed main and platform packages: the addon loads from the platform
// package built for this process's platform, and ordinary exports work on the main thread around a worker's load and
// unload. Prints the addon and the runtime it ran on. `--worker-exit=CODE` has the first worker exit with CODE after
// its checks pass, which must fail the probe.
import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {existsSync, readFileSync, realpathSync} from "node:fs";
import {createRequire} from "node:module";
import {availableParallelism, cpus, release} from "node:os";
import {dirname, join, relative} from "node:path";
import {fileURLToPath} from "node:url";
import {isMainThread, parentPort, Worker, workerData} from "node:worker_threads";
import {SecretKey, verify} from "@chainsafe/lodestar-z/blst";
import {innerShuffleList} from "@chainsafe/lodestar-z/shuffle";

function ordinaryExports() {
  const secretKey = SecretKey.fromKeygen(new Uint8Array(32).fill(7));
  const message = new Uint8Array(32).fill(1);
  assert(verify(message, secretKey.toPublicKey(), secretKey.sign(message)));
  const list = Uint32Array.of(0, 1, 2, 3, 4, 5, 6, 7, 8);
  innerShuffleList(list, new Uint8Array(32), 32, false);
  assert.deepEqual(list, Uint32Array.of(6, 2, 3, 5, 1, 7, 8, 0, 4));
}

/** Runs a worker to its exit; its checks pass only if it reported "ok" alone, raised nothing and exited with 0. */
function runWorker(exitCode) {
  return new Promise((resolve, reject) => {
    const messages = [];
    let failure;
    const worker = new Worker(new URL(import.meta.url), {workerData: {exitCode}});
    worker.on("message", (message) => messages.push(message));
    worker.once("error", (error) => {
      failure = error;
    });
    worker.once("exit", (code) => {
      if (failure) reject(failure);
      else if (code !== 0) reject(Error(`Worker exited with code ${code}`));
      else if (messages.length !== 1 || messages[0] !== "ok") reject(Error(`Worker reported ${messages}`));
      else resolve();
    });
  });
}

function command(program, args) {
  const result = spawnSync(program, args, {encoding: "utf8", timeout: 10_000});
  return `${result.stdout ?? ""}${result.stderr ?? ""}`.trim().split("\n").slice(0, 2).join(" ") || null;
}

function runtime() {
  const osRelease = existsSync("/etc/os-release")
    ? (/^PRETTY_NAME="?([^"\n]*)"?$/m.exec(readFileSync("/etc/os-release", "utf8"))?.[1] ?? null)
    : null;
  const glibc = process.report.getReport().header.glibcVersionRuntime;
  return {
    cpu: cpus()[0]?.model ?? null,
    cpus: availableParallelism(),
    kernel: release(),
    libc: process.platform !== "linux" ? null : glibc ? `glibc ${glibc}` : command("ldd", ["--version"]),
    node: process.version,
    os: process.platform === "darwin" ? `macOS ${command("sw_vers", ["-productVersion"])}` : osRelease,
    platform: `${process.platform}-${process.arch}`,
    v8: process.versions.v8,
  };
}

if (!isMainThread) {
  ordinaryExports();
  parentPort.postMessage("ok");
  if (workerData.exitCode !== 0) process.exit(workerData.exitCode);
} else {
  const exitArgument = process.argv.find((arg) => arg.startsWith("--worker-exit="));
  const firstExitCode = exitArgument === undefined ? 0 : Number(exitArgument.slice("--worker-exit=".length));
  assert(Number.isInteger(firstExitCode) && firstExitCode >= 0 && firstExitCode < 256, "invalid --worker-exit");
  const root = process.cwd();
  const consumer = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const main = "@chainsafe/lodestar-z";
  const [platformPackage, ...others] = Object.keys(consumer.dependencies).filter((name) => name.startsWith(`${main}-`));
  assert.deepEqual(others, []);
  const libc =
    process.platform !== "linux" ? "" : process.report.getReport().header.glibcVersionRuntime ? "-gnu" : "-musl";
  const arch = {arm64: "aarch64", x64: "x86_64"}[process.arch];
  const vendor = process.platform === "darwin" ? "apple-darwin" : `unknown-${process.platform}`;
  assert.equal(platformPackage, `${main}-${arch}-${vendor}${libc}`, "platform package for another platform");

  const network = await import(`${main}/network`);
  assert.deepEqual(Object.keys(network), ["createNativeNetwork"]);
  const require = createRequire(join(root, "package.json"));
  const nativePath = realpathSync(require.resolve(platformPackage));
  assert(!relative(root, nativePath).startsWith(".."));
  const native = require(nativePath);
  assert.equal(typeof native.NativeNetworkRuntime, "function");
  assert(!Object.getOwnPropertyNames(native).some((name) => /^networkTest/i.test(name)));
  const packageRoot = join(dirname(fileURLToPath(import.meta.resolve(`${main}/network`))), "../..");
  assert(!existsSync(join(packageRoot, "zig-out/lib/bindings.node")));
  assert.deepEqual(
    Object.keys(require.cache).filter((path) => path.endsWith(".node")),
    [nativePath]
  );

  ordinaryExports();
  for (let i = 0; i < 2; i++) {
    await runWorker(i === 0 ? firstExitCode : 0);
    ordinaryExports();
  }
  const addon = readFileSync(nativePath);
  console.log(
    JSON.stringify({
      addon: {
        bytes: addon.length,
        path: relative(root, nativePath),
        sha256: createHash("sha256").update(addon).digest("hex"),
      },
      loaded: true,
      platformPackage,
      runtime: runtime(),
    })
  );
}
