import bindings from "../../src/bindings.js";
import type {NativeIdentity, NativeProtocolId, NativeRequestOptions, NativeResponseChunk} from "../../src/network.js";
import type {
  NativeExchange,
  NativeExchangeDemand,
  NativeNetworkApplicationRuntime,
  NativeRuntimeCloseResult,
} from "../../src/network-runtime.js";

interface RequestHandle {
  generation: bigint;
  index: number;
}

interface NativeBridge extends Pick<NativeNetworkApplicationRuntime, "diagnostics"> {
  /** Each command returns its cell handle; its completion arrives in an exchange. */
  applyIntent(...args: Parameters<NativeNetworkApplicationRuntime["applyIntent"]>): RequestHandle;
  connect(...args: Parameters<NativeNetworkApplicationRuntime["connect"]>): RequestHandle;
  exchange(actions: readonly never[], demand: NativeExchangeDemand): NativeExchange;
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

/** Exchanges until a raw runtime delivers the completion of the command `handle` names; throws its error. */
export async function commandCompleted(
  native: Pick<NativeBridge, "exchange">,
  handle: RequestHandle,
  demand: NativeExchangeDemand,
  timeoutMs = 10000
): Promise<unknown> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const completion = native
      .exchange([], demand)
      .completions.find(
        ({family, handle: done}) =>
          family === "command" && done.index === handle.index && done.generation === handle.generation
      );
    if (completion) {
      if ("error" in completion) throw completion.error;
      return completion.value;
    }
    if (Date.now() > deadline) throw Error("Command completion did not arrive");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
