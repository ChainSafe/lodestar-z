import {beforeAll, describe, expect, it} from "vitest";
import bindings from "../src/index.js";

describe("metrics", () => {
  beforeAll(() => {
    bindings.metrics.init();
  });

  it("can scrape state transition metrics without validator monitor metrics", () => {
    const allMetrics = bindings.metrics.scrapeMetrics();
    const stateTransitionMetrics = bindings.metrics.scrapeStateTransitionMetrics();

    expect(allMetrics).toContain("lodestar_stfn_hash_tree_root_seconds");
    expect(allMetrics).toContain("validator_monitor_prev_epoch_on_chain_balance");
    expect(stateTransitionMetrics).toContain("lodestar_stfn_hash_tree_root_seconds");
    expect(stateTransitionMetrics).not.toContain("validator_monitor_");
  });
});
