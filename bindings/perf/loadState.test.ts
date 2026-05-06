import {config} from "@lodestar/config/default";
import * as era from "@lodestar/era";
import {loadState as loadStateTS} from "@lodestar/state-transition";
import {ssz} from "@lodestar/types";
import {bench, describe} from "@chainsafe/benchmark";
import bindings from "../src/index.js";
import {getFirstEraFilePath} from "../test/eraFiles.ts";

const reader = await era.era.EraReader.open(config, getFirstEraFilePath());
const stateBytes = await reader.readSerializedState();
await reader.close();

bindings.pool.ensureCapacity(10_000_000);
bindings.pubkeys.ensureCapacity(2_000_000);
try {
  bindings.pubkeys.load("./mainnet.pkix");
} catch (_e) {
  // ignore
}

const seedState = bindings.BeaconStateView.createFromBytes(stateBytes);
const seedValidatorsBytes = seedState.serializeValidators();

const tsSeedState = ssz.fulu.BeaconState.deserializeToViewDU(stateBytes);

describe("loadState: native vs TS (mainnet)", () => {
  bench({
    fn: () => {
      seedState.loadOtherState(stateBytes);
    },
    id: "native (internal serialize seed)",
  });

  bench({
    fn: () => {
      loadStateTS(config, tsSeedState, stateBytes);
    },
    id: "TS (internal serialize seed)",
  });

  bench({
    fn: () => {
      seedState.loadOtherState(stateBytes, seedValidatorsBytes);
    },
    id: "native (prebuilt seedValidatorsBytes)",
  });

  bench({
    fn: () => {
      loadStateTS(config, tsSeedState, stateBytes, seedValidatorsBytes);
    },
    id: "TS (prebuilt seedValidatorsBytes)",
  });
});
