import {createChainForkConfig} from "@lodestar/config";
import {mainnetChainConfig} from "@lodestar/config/configs";
import {networksChainConfig} from "@lodestar/config/networks";
import {describe, expect, it} from "vitest";
import bindings from "../src/index.js";

describe("config parses JS object config into zig native config", () => {
  for (const [name, chainConfig] of Object.entries(networksChainConfig)) {
    if (chainConfig.PRESET_BASE !== mainnetChainConfig.PRESET_BASE) continue;

    it(`sets ${name}`, () => {
      const config = createChainForkConfig(
        name === "ephemery"
          ? {...chainConfig, DEPOSIT_CHAIN_ID: 39438000, DEPOSIT_NETWORK_ID: 39438000, MIN_GENESIS_TIME: 1638471600}
          : chainConfig
      );
      expect(() => bindings.config.set(config, new Uint8Array(32))).not.toThrow();
    });
  }
});
