// The packaged consumer's scenarios, in the order network-package.mjs runs them, with their arguments relative to the
// consumer's root. Publishing requires each target's lifecycle qualification to have run each of these exactly once and
// passed (scripts/release_artifacts.mjs).
const fixture = (name) => `bindings/test/fixtures/${name}`;
const lifecycleFixture = (mode, expected) => ({
  args: ["--import", "tsx", "--expose-gc", fixture("network-lifecycle.mjs"), mode],
  expected,
  name: mode,
});
const probe = ["--experimental-import-meta-resolve", fixture("network-package-probe.mjs")];

/** The load probe's scenarios and, with `lifecycle`, the lifecycle and worker fixtures. */
export function packageScenarios(lifecycle) {
  return [
    {args: probe, expected: '"loaded":true', name: "load"},
    // The probe must fail when a worker passes its checks but exits nonzero.
    {args: [...probe, "--worker-exit=7"], name: "worker exit code", rejected: "Worker exited with code 7"},
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
}
