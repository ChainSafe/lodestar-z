import type {
  NativeApplicationConfig,
  NativeHost,
  NativeNetwork,
  NativePeerObservation,
  NativePeerState,
} from "../../src/network.js";
import type {NativeNetworkApplicationRuntime} from "../../src/network-runtime.js";
export function initializeNativeNetworkRuntime(
  config: NativeApplicationConfig,
  onWorkAvailable: () => void,
  onPeers?: (events: readonly NativePeerObservation[]) => void
): NetworkTestRuntime;
export function createNativeNetwork(config: NativeApplicationConfig, host: NativeHost): NativeNetwork;
export function runtimeOf(network: NativeNetwork): NativeNetworkApplicationRuntime | undefined;

/** Views assembled by the test adapter from observations delivered through exchange. */
export interface NetworkTestRuntime extends NativeNetworkApplicationRuntime {
  getIdentity: NativeNetwork["getIdentity"];
  getDirectPeers: NativeNetwork["getDirectPeers"];
  getPeers(): Promise<{peers: NativePeerState[]; counts: {connected: number; relevant: number}}>;
}
