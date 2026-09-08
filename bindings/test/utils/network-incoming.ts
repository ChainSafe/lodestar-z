import {setTimeout as delay} from "node:timers/promises";
import type {
  NativeApplicationConfig,
  NativeIncomingRequest,
  NativeNetworkApplicationRuntime,
} from "../../src/network.js";
import {createNativeNetworkApplicationRuntime} from "../../src/network.js";
import {applicationConfig, localIntent} from "./network.js";

export const BLOCKS = "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy";

export async function incomingPair(
  beforeServer?: () => void,
  serverBudget?: number,
  onServerReadable: () => void = () => undefined,
  configure?: (left: NativeApplicationConfig, right: NativeApplicationConfig) => void
) {
  const leftConfig = applicationConfig();
  const rightConfig = applicationConfig();
  leftConfig.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
  rightConfig.resources.bridgeBudgetBytes = serverBudget ?? 512 * 1024 * 1024;
  rightConfig.identitySecretKey[31] = 2;
  for (const config of [leftConfig, rightConfig]) {
    config.requestForks.push({digest: Uint8Array.of(5, 6, 7, 8), fork: "deneb"});
  }
  configure?.(leftConfig, rightConfig);
  let left: NativeNetworkApplicationRuntime | undefined;
  let right: NativeNetworkApplicationRuntime | undefined;
  try {
    left = createNativeNetworkApplicationRuntime(leftConfig, () => undefined);
    void left.ready.catch(() => undefined);
    beforeServer?.();
    right = createNativeNetworkApplicationRuntime(rightConfig, onServerReadable);
    const [identity, remote] = await Promise.all([left.ready, right.ready]);
    await Promise.all([
      left.applyIntent(localIntent(leftConfig), leftConfig.initialSlot),
      right.applyIntent(localIntent(rightConfig), rightConfig.initialSlot),
    ]);
    await left.connect(remote.peerId, [remote.localEndpoint], 5000n);
    return {identity, left, leftConfig, remote, right, rightConfig};
  } catch (error) {
    await Promise.allSettled([left?.close(), right?.close()]);
    throw error;
  }
}

export async function takeIncoming(runtime: NativeNetworkApplicationRuntime): Promise<NativeIncomingRequest> {
  for (let i = 0; i < 1000; i++) {
    const incoming = runtime.takeIncomingRequest();
    if (incoming) return incoming;
    await delay(5);
  }
  throw Error("Incoming request deadline");
}
