import {beforeAll, describe, expect, it} from "vitest";
import bindings, {type StateHashTreeRootSource} from "../src/index.js";

const sources = [
  "state_transition",
  "block_transition",
  "prepare_next_slot",
  "prepare_next_epoch",
  "regen_state",
  "compute_new_state_root",
] as const satisfies StateHashTreeRootSource[];

describe("metrics", () => {
  beforeAll(() => {
    bindings.metrics.init();
  });

  it.each(sources)("records an external %s hash tree root duration", (source) => {
    const seconds = source === "block_transition" ? 0.125 : 0.001;
    bindings.metrics.observeStateHashTreeRoot(source, seconds);

    const output = bindings.metrics.scrapeMetrics();
    expect(output).toContain(`lodestar_stfn_hash_tree_root_seconds_count{source="${source}"} 1`);
    expect(output).toContain(`lodestar_stfn_hash_tree_root_seconds_sum{source="${source}"} ${seconds}`);
  });

  it("can scrape state transition metrics without validator monitor metrics", () => {
    const allMetrics = bindings.metrics.scrapeMetrics();
    const stateTransitionMetrics = bindings.metrics.scrapeStateTransitionMetrics();

    expect(allMetrics).toContain("lodestar_stfn_hash_tree_root_seconds");
    expect(allMetrics).toContain("validator_monitor_prev_epoch_on_chain_balance");
    expect(stateTransitionMetrics).toContain("lodestar_stfn_hash_tree_root_seconds");
    expect(stateTransitionMetrics).not.toContain("validator_monitor_");
  });

  it("accepts the maximum duration", () => {
    expect(() => bindings.metrics.observeStateHashTreeRoot("block_transition", 60 * 60)).not.toThrow();
  });

  it.each([
    {error: "InvalidStateHashTreeRootSource", seconds: 0, source: "invalid"},
    {error: "InvalidMetricDuration", seconds: -1, source: "block_transition"},
    {error: "InvalidMetricDuration", seconds: Number.NaN, source: "block_transition"},
    {error: "InvalidMetricDuration", seconds: Number.POSITIVE_INFINITY, source: "block_transition"},
    {error: "InvalidMetricDuration", seconds: 60 * 60 + 1, source: "block_transition"},
  ])("rejects invalid observation $error", ({source, seconds, error}) => {
    const observeStateHashTreeRoot = bindings.metrics.observeStateHashTreeRoot as unknown as (
      source: string,
      seconds: number
    ) => void;

    expect(() => observeStateHashTreeRoot(source, seconds)).toThrow(error);
  });
});
