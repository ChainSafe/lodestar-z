// TODO make robust for production use ala bun-ffi-z

import {createRequire} from "node:module";
import {join} from "node:path";

const require = createRequire(import.meta.url);

type Bindings = {
  pool: {
    init: (poolSize: number) => void;
    deinit: () => void;
    isInitialized: () => boolean;
  };
};

export default require(join(import.meta.dirname, "../../zig-out/lib/bindings.node")) as Bindings;
