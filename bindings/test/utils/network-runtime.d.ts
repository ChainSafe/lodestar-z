import type {NativeApplicationConfig, NativeHost, NativeNetwork} from "../../src/network.js";
import type {NativeNetworkApplicationRuntime} from "../../src/network-runtime.js";
export function initializeNativeNetworkRuntime(
  config: NativeApplicationConfig,
  onWorkAvailable: () => void
): NativeNetworkApplicationRuntime;
export function createNativeNetwork(config: NativeApplicationConfig, host: NativeHost): NativeNetwork;
export function runtimeOf(network: NativeNetwork): NativeNetworkApplicationRuntime | undefined;
