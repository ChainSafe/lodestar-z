import bindings from "../../src/bindings.js";
import type {NativeIdentity, NativeRequestOptions, NativeRequestProtocolId} from "../../src/network.js";
import type {
  NativeCompletion,
  NativeExchange,
  NativeExchangeDemand,
  NativeNetworkApplicationRuntime,
  NativeRuntimeCloseResult,
} from "../../src/network-runtime.js";

interface RequestHandle {
  generation: bigint;
  index: number;
}

interface NativeBridge {
  /** Each command returns its cell handle; its completion arrives in an exchange. */
  applyIntent(...args: Parameters<NativeNetworkApplicationRuntime["applyIntent"]>): RequestHandle;
  connect(...args: Parameters<NativeNetworkApplicationRuntime["connect"]>): RequestHandle;
  exchange(actions: readonly never[], demand: NativeExchangeDemand): NativeExchange;
  close(): void;
  initialize(config: unknown, onWorkAvailable: () => void): {identity: NativeIdentity};
  requestStart(
    peer: string,
    protocol: NativeRequestProtocolId,
    data: Uint8Array,
    options: NativeRequestOptions | undefined
  ): RequestHandle;
  /** Arms a pull, whose chunk or terminal outcome a request completion delivers. */
  requestPull(handle: RequestHandle): void;
  /** Cancels the request, whose terminal completion ends the retirement. */
  requestRetire(handle: RequestHandle, abandoned: boolean): void;
}

interface NetworkTestBindings {
  NativeNetworkRuntime: new () => NativeBridge;
}

export const networkBindings = bindings as NetworkTestBindings;

/** Exchanges until a raw runtime delivers a completion of `family` for the cell `handle` names, and returns it. */
export async function completed(
  native: Pick<NativeBridge, "exchange">,
  family: NativeCompletion["family"],
  handle: RequestHandle,
  demand: NativeExchangeDemand,
  timeoutMs = 10000
): Promise<NativeCompletion> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const completion = native
      .exchange([], demand)
      .completions.find(
        (done) =>
          done.family === family && done.handle.index === handle.index && done.handle.generation === handle.generation
      );
    if (completion) return completion;
    if (Date.now() > deadline) throw Error(`The ${family} completion did not arrive`);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

/** Exchanges until a raw runtime delivers the completion of the command `handle` names; throws its error. */
export async function commandCompleted(
  native: Pick<NativeBridge, "exchange">,
  handle: RequestHandle,
  demand: NativeExchangeDemand,
  timeoutMs = 10000
): Promise<unknown> {
  const completion = await completed(native, "command", handle, demand, timeoutMs);
  if ("error" in completion) throw completion.error;
  return "value" in completion ? completion.value : undefined;
}

/** Closes a raw runtime and exchanges until one delivers its close result, which it returns. */
export async function closedBy(
  native: Pick<NativeBridge, "close" | "exchange">,
  demand: NativeExchangeDemand,
  timeoutMs = 10000
): Promise<NativeRuntimeCloseResult> {
  native.close();
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const {closed} = native.exchange([], demand);
    if (closed !== null) return closed;
    if (Date.now() > deadline) throw Error("The close result did not arrive");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
