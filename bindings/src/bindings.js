import {join} from "node:path";
import {requireNapiLibrary} from "@chainsafe/zapi";

const bindings = requireNapiLibrary(join(import.meta.dirname, "../.."));

// Namespace-level constants mirroring @chainsafe/swap-or-not-shuffle; the
// zapi DSL only auto-exports functions and classes, so values are attached
// here instead of via a native register hook.
bindings.shuffle.SHUFFLE_ROUNDS_MAINNET = 90;
bindings.shuffle.SHUFFLE_ROUNDS_MINIMAL = 10;
bindings.shuffle.ByteCount = {One: 1, Two: 2};

export default bindings;
