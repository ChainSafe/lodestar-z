// Runs, from the root of a consumer that installed the packed main and platform packages, the load probe and, with
// --lifecycle, the lifecycle and worker fixtures, each in its own bounded process, and records the addon, runtime and
// results in qualification.json. LODESTAR_Z_TIMEOUT_SCALE stretches each process's deadline for emulated targets.
import {writeFile} from "node:fs/promises";
import {runBoundedCommand} from "../../../scripts/bounded_child.mjs";

const lifecycle = process.argv.includes("--lifecycle");
const scale = Number(process.env.LODESTAR_Z_TIMEOUT_SCALE ?? "1");
if (!Number.isInteger(scale) || scale < 1 || scale > 20) throw Error("LODESTAR_Z_TIMEOUT_SCALE must be 1..20");

const fixture = (name) => `bindings/test/fixtures/${name}`;
const lifecycleFixture = (mode, expected) => ({
  args: ["--import", "tsx", "--expose-gc", fixture("network-lifecycle.mjs"), mode],
  expected,
  name: mode,
});
const probe = fixture("network-package-probe.mjs");
const scenarios = [
  {args: [probe], expected: '"loaded":true', name: "load"},
  // The probe must fail when a worker passes its checks but exits nonzero.
  {args: [probe, "--worker-exit=7"], name: "worker exit code", rejected: "Worker exited with code 7"},
  ...(lifecycle
    ? [
        {
          args: ["--import", "tsx", fixture("network-worker-unload.mjs")],
          expected: "workers-exited 0,0,0",
          name: "worker-only loads",
        },
        {
          args: ["--import", "tsx", fixture("network-worker-settlement.mjs")],
          expected: "worker-settlement-released",
          name: "worker termination with publications",
        },
        {
          args: ["--import", "tsx", fixture("network-worker-resources.mjs")],
          expected: "live-worker-resources-released",
          name: "worker termination with requests and incoming",
        },
        lifecycleFixture("incoming-exit", "served-exit"),
        lifecycleFixture("promises", "promises-settled"),
        lifecycleFixture("saturated-close", "saturated-closed"),
        lifecycleFixture("gc", "gc-rebound"),
        lifecycleFixture("facade-gc", "facade-collected"),
        lifecycleFixture("await-close", "close-awaited"),
        {
          args: ["--import", "tsx", fixture("network-shutdown-retry.mjs")],
          // Close settles, or the third failed exchange aborts through native `fail`; exiting with neither fails.
          escalation: "native network bridge failed_turns: exchange failed",
          expected: "closed",
          name: "shutdown failure",
        },
      ]
    : []),
];

const results = [];
let probed = null;
for (const scenario of scenarios) {
  const started = Date.now();
  let record;
  let error;
  try {
    record = await runBoundedCommand(process.execPath, scenario.args, process.cwd(), {
      allowFailure: true,
      maxOutputBytes: 1024 * 1024,
      timeoutMs: 30_000 * scale,
    });
  } catch (thrown) {
    error = thrown;
    record = thrown.commandRecord;
  }
  const completed =
    error === undefined &&
    scenario.expected !== undefined &&
    record.exitCode === 0 &&
    record.stdout.includes(scenario.expected);
  const escalated =
    error === undefined &&
    scenario.escalation !== undefined &&
    record.signal === "SIGABRT" &&
    record.stderr.includes(scenario.escalation);
  const rejected =
    error === undefined &&
    scenario.rejected !== undefined &&
    record.exitCode !== 0 &&
    record.stderr.includes(scenario.rejected);
  const passed = completed || escalated || rejected;
  if (completed && scenario.args.length === 1 && scenario.args[0] === probe)
    probed = JSON.parse(record.stdout.trim().split("\n").at(-1));
  const result = {ms: Date.now() - started, name: scenario.name, passed, ...(escalated ? {escalated} : {})};
  if (!passed) {
    Object.assign(result, {
      error: error?.message,
      exitCode: record?.exitCode,
      signal: record?.signal,
      stderr: record?.stderr.slice(-4000),
      stdout: record?.stdout.slice(-2000),
    });
  }
  results.push(result);
  console.log(JSON.stringify(result));
}
const failed = results.filter((result) => !result.passed).length;
await writeFile(
  "qualification.json",
  `${JSON.stringify({...probed, failed, lifecycle, results, timeoutScale: scale}, null, 2)}\n`
);
console.log(JSON.stringify({failed, scenarios: scenarios.length}));
process.exitCode = failed === 0 ? 0 : 1;
