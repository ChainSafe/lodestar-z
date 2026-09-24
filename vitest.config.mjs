import {defineConfig} from "vitest/config";

export default defineConfig({
  test: {
    pool: "forks",
    maxWorkers: 2,
    setupFiles: ["./bindings/test/utils/network-setup.ts"],
  },
});
