import {config} from "@lodestar/config/default";
import * as era from "@lodestar/era";
import * as fs from "fs";
import bindings from "../src/index.ts";

console.log("loaded bindings");

function printDuration<R>(label: string, fn: () => R): R {
  console.time(label);
  const result = fn();
  console.timeEnd(label);
  return result;
}

async function printDurationAsync<R>(label: string, fn: () => Promise<R>): Promise<R> {
  console.time(label);
  const result = await fn();
  console.timeEnd(label);
  return result;
}

const PKIX_FILE = "./mainnet.pkix";
const hasPkix = printDuration("check for pkix file", () => {
  try {
    fs.accessSync(PKIX_FILE);
    return true;
  } catch {
    return false;
  }
});

if (hasPkix) {
  printDuration("load pkix from disk", () => bindings.pubkeys.load(PKIX_FILE));
} else {
  printDuration("update bindings capacity", () => {
    bindings.pool.ensureCapacity(10_000_000);
    bindings.pubkeys.ensureCapacity(2_000_000);
  });
}

const reader = await printDurationAsync("load era reader", () =>
  era.era.EraReader.open(config, "./fixtures/era/mainnet-01628-47ac89fb.era")
);

const stateBytes = await printDurationAsync("read serialized state", () => reader.readSerializedState());

const state = printDuration("create state view", () => bindings.BeaconStateView.createFromBytes("fulu", stateBytes));

printDuration("write pkix to disk", () => bindings.pubkeys.save(PKIX_FILE));

printDuration("get slot", () => state.slot);
printDuration("get root", () => state.root);
printDuration("get epoch", () => state.epoch);
printDuration("get genesisTime", () => state.genesisTime);
printDuration("get genesisValidatorsRoot", () => state.genesisValidatorsRoot);
printDuration("get latestBlockHeader", () => state.latestBlockHeader);
printDuration("get previousJustifiedCheckpoint", () => state.previousJustifiedCheckpoint);
printDuration("get currentJustifiedCheckpoint", () => state.currentJustifiedCheckpoint);
printDuration("proposers", () => state.proposers);
printDuration("proposersNextEpoch", () => state.proposersNextEpoch);
printDuration("getBalance(0)", () => state.getBalance(0));
printDuration("getBalance(100)", () => state.getBalance(100));
printDuration("getFinalizedRootProof()", () => state.getFinalizedRootProof());
printDuration("isExecutionStateType()", () => state.isExecutionStateType());
printDuration("getEffectiveBalanceIncrementsZeroInactive()", () => state.getEffectiveBalanceIncrementsZeroInactive());
printDuration("computeUnrealizedCheckpoints()", () => state.computeUnrealizedCheckpoints());
