import bindings from "../../src/bindings.js";
import type {
  HostCapacity,
  NativeIdentity,
  NativeRequestOptions,
  NativeRequestProtocolId,
  NativeResponseChunk,
} from "../../src/network.js";
import type {
  NativeExchange,
  NativeNetworkApplicationRuntime,
  NativeRuntimeCloseResult,
} from "../../src/network-runtime.js";

interface RequestHandle {
  generation: bigint;
  index: number;
}

interface NativeBridge {
  /** Operations return native-owned Promises, settled by completion draining. */
  applyIntent: NativeNetworkApplicationRuntime["applyIntent"];
  connect: NativeNetworkApplicationRuntime["connect"];
  exchange(): NativeExchange;
  setCapacity(capacity: HostCapacity | null): void;
  drainCompletions(): boolean;
  close(): void;
  initialize(
    config: unknown,
    onWorkAvailable: () => void
  ): {identity: NativeIdentity; closed: Promise<NativeRuntimeCloseResult>};
  requestStart(
    peer: string,
    protocol: NativeRequestProtocolId,
    data: Uint8Array,
    options: NativeRequestOptions | undefined
  ): {handle: RequestHandle; closed: Promise<Error | null>};
  /** Arms a pull, whose chunk or terminal outcome a request completion delivers. */
  requestPull(handle: RequestHandle): Promise<IteratorResult<NativeResponseChunk>>;
  /** Cancels the request, whose terminal completion ends the retirement. */
  requestRetire(handle: RequestHandle, abandoned: boolean): void;
}

interface NetworkTestBindings {
  NativeNetworkRuntime: new () => NativeBridge;
}

export const networkBindings = bindings as NetworkTestBindings;

/** Drains a runtime until the native-owned Promise settles. */
export async function drainUntil<T>(
  native: Pick<NativeBridge, "drainCompletions">,
  command: Promise<T>,
  timeoutMs = 10000
): Promise<T> {
  let settled = false;
  void command.then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    }
  );
  const deadline = Date.now() + timeoutMs;
  while (!settled) {
    native.drainCompletions();
    if (Date.now() > deadline) throw Error("The native Promise did not settle");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  return command;
}

/** Closes and drains native Promises without taking payloads. */
export async function closedBy(
  native: Pick<NativeBridge, "close" | "drainCompletions">,
  closed: Promise<NativeRuntimeCloseResult>,
  timeoutMs = 10000
): Promise<NativeRuntimeCloseResult> {
  native.close();
  return drainUntil(native, closed, timeoutMs);
}
