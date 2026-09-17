# Binding benchmarks

`pnpm benchmark` runs each `bindings/perf/**/*.test.ts` file sequentially in a fresh Node process. The parent retains the benchmark framework's CLI, comparison logic, combined CSV history, regression exit status, and single GitHub report. Workers inherit the parent's Node executable, runtime flags, environment, and working directory. A worker must exit successfully with a complete file result before the next file starts or any combined result is persisted.

Process isolation prevents the mainnet state retained by `loadState.test.ts` and its garbage-collection work from contaminating unrelated native benchmarks. The allocating shuffle API, deterministic inputs, thresholds, and result IDs remain unchanged. This is isolation between files, not between individual cases within a file.

The default local history is `benchmark_data/isolated-v1`. CI also uses a distinct `benchmark-data-isolated-v1-` cache prefix. Shared-process measurements are not comparable with these results; let a fresh baseline accumulate rather than copying the old CSVs.

Custom runners can invoke the upstream `@chainsafe/benchmark` CLI with `--isolate`:

```sh
NODE_OPTIONS='--max-old-space-size=4096 --import tsx' pnpm exec benchmark \
  'bindings/perf/**/*.test.ts' --isolate --config .benchrc.yaml --defaultBranch main \
  --local /path/to/new-isolated-history --persist
```

An explicit history override remains caller-owned: choose a new directory or profile identity when migrating a dedicated monitor. Omit a bare `--local` flag; the configuration already selects local storage. Keep the host, heap, cgroup policy, and fixture identity fixed when comparing measurements.

Isolation is provided by the public `--isolate` option in `@chainsafe/benchmark` 2.1.0; there is no local runner adapter. When upgrading the dependency, run `pnpm exec vitest run bindings/test/benchmarkRunner.test.ts` and a complete benchmark pass. Collection errors, benchmark failures, worker crashes, and duplicate IDs must fail without persisting partial results.
