import {bench, describe} from "@chainsafe/benchmark";
import {config} from "@lodestar/config/default";
import * as era from "@lodestar/era";
import {loadState as loadStateTS} from "@lodestar/state-transition";
import {ssz} from "@lodestar/types";
import bindings from "../src/index.js";
import {createPubkeyCache} from "../src/pubkeys.js";
import {getFirstEraFilePath} from "../test/eraFiles.ts";

const reader = await era.era.EraReader.open(config, getFirstEraFilePath());
const stateBytes = await reader.readSerializedState();
await reader.close();

bindings.pool.ensureCapacity(10_000_000);
const pubkeyCache = createPubkeyCache();
pubkeyCache.ensureCapacity(2_000_000);
try {
  pubkeyCache.load("./mainnet.pkix");
} catch (_e) {
  // ignore
}

const seedState = pubkeyCache.createBeaconStateView(stateBytes);
const seedValidatorsBytes = seedState.serializeValidators();

const tsSeedState = ssz.fulu.BeaconState.deserializeToViewDU(stateBytes);

describe("loadState: native vs TS (mainnet)", () => {
  bench({
    fn: () => {
      seedState.loadOtherStateBench(stateBytes);
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
      seedState.loadOtherStateBench(stateBytes, seedValidatorsBytes);
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
