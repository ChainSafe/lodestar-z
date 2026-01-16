// TODO make robust for production use ala bun-ffi-z

import {createRequire} from "node:module";
import {join} from "node:path";

const require = createRequire(import.meta.url);

type Bindings = {
  pool: {
    ensureCapacity: (capacity: number) => void;
  };
  pubkey2index: {
    ensureCapacity: (capacity: number) => void;
    get: (pubkey: Uint8Array) => number | undefined;
  };
  index2pubkey: {
    ensureCapacity: (capacity: number) => void;
    get: (index: number) => Uint8Array | undefined;
  };
  config: {
    set: (chainConfig: object, genesisValidatorsRoot: Uint8Array) => void;
  };
  epoch: {
    computeEpochAtSlot: (slot: number) => number;
  };
  deinit: () => void;
};

export default require(join(import.meta.dirname, "../../zig-out/lib/bindings.node")) as Bindings;
