import {ssz} from "@lodestar/types";

/** Ninety days of worst-case validator-registry growth on the mainnet preset. */
export const DEFAULT_PUBKEY_CACHE_HEADROOM = 324_000;

const validatorFieldIndex = Object.keys(ssz.fulu.BeaconState.fields).indexOf("validators");
const validatorSize = ssz.phase0.Validator.fixedSize;

if (validatorFieldIndex === -1 || validatorSize === null) {
  throw new Error("Unable to locate the fixed-size validator list in Fulu BeaconState SSZ");
}

/** Read the validator count directly from SSZ offsets without constructing a tree view. */
export function getSerializedFuluValidatorCount(stateBytes: Uint8Array): number {
  const dataView = new DataView(stateBytes.buffer, stateBytes.byteOffset, stateBytes.byteLength);
  const range = ssz.fulu.BeaconState.getFieldRanges(dataView, 0, stateBytes.byteLength)[validatorFieldIndex];
  const byteLength = range.end - range.start;
  if (byteLength % validatorSize !== 0) {
    throw new Error(`Invalid serialized validator list length: ${byteLength}`);
  }
  return byteLength / validatorSize;
}

export function getPubkeyCacheCapacityForState(
  stateBytes: Uint8Array,
  headroom = DEFAULT_PUBKEY_CACHE_HEADROOM
): number {
  return getSerializedFuluValidatorCount(stateBytes) + headroom;
}
