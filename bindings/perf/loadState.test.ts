import {bench, describe} from "@chainsafe/benchmark";
import {config} from "@lodestar/config/default";
import * as era from "@lodestar/era";
import {loadState as loadStateTS} from "@lodestar/state-transition";
import {ssz} from "@lodestar/types";
import bindings from "../src/index.js";
import {getFirstEraFilePath} from "../test/eraFiles.ts";
import {getPubkeyCacheCapacityForState} from "../test/serializedState.ts";

const reader = await era.era.EraReader.open(config, getFirstEraFilePath());
const stateBytes = await reader.readSerializedState();
await reader.close();
const requiredPubkeyCapacity = getPubkeyCacheCapacityForState(stateBytes);

bindings.pool.ensureCapacity(10_000_000);
let loadedPkix = false;
try {
  bindings.pubkeys.load("./mainnet.pkix", requiredPubkeyCapacity);
  loadedPkix = true;
} catch (_e) {
  // Rebuild incompatible or corrupt snapshots from the serialized state.
}
if (!loadedPkix || bindings.pubkeys.capacity() < requiredPubkeyCapacity) {
  bindings.pubkeys.ensureCapacity(requiredPubkeyCapacity);
}

const seedState = bindings.BeaconStateView.createFromBytes(stateBytes);
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
