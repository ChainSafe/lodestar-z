import bindings from "../../src/bindings.js";
import type {
  NativeIdentity,
  NativeNetworkApplicationRuntime,
  NativeProtocolId,
  NativeRequestOptions,
  NativeResponseChunk,
  NativeRuntimeCloseResult,
} from "../../src/network.js";

interface RequestHandle {
  generation: bigint;
  index: number;
}

interface NativeBridge extends Pick<NativeNetworkApplicationRuntime, "applyIntent" | "connect" | "diagnostics"> {
  close(): void;
  initialize(
    config: unknown,
    onWorkAvailable: () => void
  ): {identity: NativeIdentity; closed: Promise<NativeRuntimeCloseResult>};
  requestStart(
    peer: string,
    protocol: NativeProtocolId,
    data: Uint8Array,
    options: NativeRequestOptions | undefined
  ): RequestHandle;
  requestPull(handle: RequestHandle): Promise<IteratorResult<NativeResponseChunk, undefined>>;
  requestRetire(handle: RequestHandle, abandoned: boolean): Promise<void> | undefined;
}

interface NetworkTestBindings {
  NativeNetworkRuntime: new () => NativeBridge;
}

export const networkBindings = bindings as NetworkTestBindings;
