// TODO make robust for production use ala bun-ffi-z

import {createRequire} from "node:module";
import {join} from "node:path";

const require = createRequire(import.meta.url);

type Bindings = {
  pool: {
    init: (poolSize: number) => void;
    deinit: () => void;
  };
  pubkey2index: {
    init: (initialCapacity?: number) => void;
    deinit: () => void;
    get: (pubkey: Uint8Array) => number | undefined;
  };
  index2pubkey: {
    init: (initialCapacity?: number) => void;
    deinit: () => void;
    get: (index: number) => Uint8Array | undefined;
  };
  config: {
    init: (chainConfig: object, genesisValidatorsRoot: Uint8Array) => void;
    deinit: () => void;
  };
};

export default require(join(import.meta.dirname, "../../zig-out/lib/bindings.node")) as Bindings;
