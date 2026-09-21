import {defineConfig} from "vitest/config";

export default defineConfig({
  test: {
    pool: "forks",
    maxWorkers: 2,
    runner: "./bindings/test/utils/network-runner.mjs",
  },
});
