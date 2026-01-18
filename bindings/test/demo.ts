import {config} from '@lodestar/config/default';
import * as era from '@lodestar/era';
import bindings from '../src/index.ts';

console.log('loaded bindings');

bindings.pool.ensureCapacity(10_000_000);
bindings.index2pubkey.ensureCapacity(2_000_000);

console.log('updated bindings capacity');

const reader = await era.era.EraReader.open(config, './fixtures/era2/mainnet-01628-47ac89fb.era');

console.log('loaded era reader');

const stateBytes = await reader.readSerializedState();

console.log('loaded state bytes');

const state = bindings.BeaconStateView.createFromBytes('fulu', stateBytes);

console.log('loaded state view');

console.log(state.slot);
console.log(state.root);
console.log(state.epoch);
console.log(state.genesisTime);
console.log(state.genesisValidatorsRoot);
console.log(state.latestBlockHeader);
console.log(state.previousJustifiedCheckpoint);
console.log(state.currentJustifiedCheckpoint);