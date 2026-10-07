import {expect, test} from "vitest";
import type {NativeForkEntry, NativeIdentity} from "../src/network.js";
import type {NativeAction, NativeExchange, NativeExchangeDemand} from "../src/network-runtime.js";
import {
  applicationConfig,
  childTestTimeout,
  gossipAll,
  localIntent,
  requestForks,
  runChild,
  settleOnly,
} from "./utils/network.js";
import {BLOCKS} from "./utils/network-incoming.js";
import {startPeer} from "./utils/network-peer.js";

test.each(["exit", "object-gc", "ready-close", "late-retire", "held-ack", "held-closed", "notifier"])(
  "incoming lifecycle subprocess %s",
  childTestTimeout(),
  (mode) => {
    const output = runChild([
      "--import",
      "tsx",
      "--expose-gc",
      "bindings/test/fixtures/network-incoming-lifecycle.mjs",
      mode,
    ]);
    expect(output).toContain(`incoming-lifecycle ${mode} ok`);
  }
);

interface IncomingHandle {
  index: number;
  generation: bigint;
}
interface IncomingDescriptor {
  handle: IncomingHandle;
}
interface DirectIncomingBridge {
  initialize(config: ReturnType<typeof applicationConfig>, onWorkAvailable: () => void): {identity: NativeIdentity};
  applyIntent(intent: ReturnType<typeof localIntent>, slot: bigint): IncomingHandle;
  exchange(
    actions: readonly NativeAction[],
    demand: NativeExchangeDemand
  ): NativeExchange & {serving: IncomingDescriptor[]};
  incomingTerminal(handle: IncomingHandle, action: number, status?: number, message?: Uint8Array): void;
  incomingRelease(handle: IncomingHandle): void;
  incomingRespond(handle: IncomingHandle, data: Uint8Array, context: NativeForkEntry): void;
  requestPull(handle: IncomingHandle): void;
  close(): void;
}

test("incoming tokens reject malformed handles and stale slot generations", async () => {
  const {closedBy, commandCompleted, completed, networkBindings: exports} = await import("./utils/network-bindings.js");
  const {NativeNetworkRuntime} = exports as unknown as {NativeNetworkRuntime: new () => DirectIncomingBridge};
  const config = applicationConfig();
  config.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
  config.identitySecretKey[31] = 2;
  const clientConfig = applicationConfig();
  clientConfig.resources.bridgeBudgetBytes = 512 * 1024 * 1024;
  const client = await startPeer(clientConfig);
  const native = new NativeNetworkRuntime();
  try {
    const promises = native.initialize(config, () => undefined);
    const [, identity] = await Promise.all([client.identity, promises.identity]);
    const intent = native.applyIntent(localIntent(config), config.initialSlot);
    await client.applyIntent(localIntent(clientConfig), clientConfig.initialSlot);
    await commandCompleted(native, intent, settleOnly);
    await client.connect(identity.peerId, [identity.localEndpoint], 5000n);
    let previous: IncomingHandle | undefined;
    for (let i = 0; i < 2; i++) {
      const stream = client.request(identity.peerId, BLOCKS, new Uint8Array(32));
      const pending = stream.next();
      void pending.catch(() => undefined);
      let incoming: IncomingDescriptor | null = null;
      await expect
        .poll(
          () => {
            // Peer events are taken too, so nothing waits.
            incoming = native.exchange([], {...gossipAll, servingStarts: 1}).serving[0] ?? null;
            return incoming !== null;
          },
          {timeout: 5000}
        )
        .toBe(true);
      if (!incoming) throw Error("missing incoming descriptor");
      const descriptor = incoming as IncomingDescriptor;
      const handle = descriptor.handle;
      for (const invalid of [{...handle, index: -1}])
        expect(() => native.incomingTerminal(invalid, 2, undefined, undefined)).toThrow("InvalidNetworkInteger");
      expect(() => native.requestPull(handle)).toThrow();
      if (previous) {
        native.incomingRespond(handle, new Uint8Array(4000), requestForks[0]);
        expect(handle.index).toBe(previous.index);
        expect(handle.generation).toBe(previous.generation + 1n);
        const stale = previous;
        expect(() => native.incomingTerminal(stale, 2, undefined, undefined)).toThrow("NetworkIncomingClosed");
        expect(await completed(native, "incoming", handle, settleOnly)).toEqual({
          family: "incoming",
          handle,
          response: {},
        });
        expect((await pending).done).toBe(false);
      }
      native.incomingTerminal(handle, 0, undefined, undefined);
      expect(await completed(native, "incoming", handle, settleOnly)).toEqual({
        closed: true,
        family: "incoming",
        handle,
      });
      native.incomingRelease(handle);
      await expect
        .poll(() => {
          try {
            native.incomingRelease(handle);
            return null;
          } catch (error) {
            return error;
          }
        })
        .toMatchObject({code: "NetworkIncomingClosed"});
      const done = previous ? stream.next() : pending;
      expect((await done).done).toBe(true);
      previous = handle;
    }
  } finally {
    await Promise.all([client.stop(), closedBy(native, settleOnly)]);
  }
}, 15000);
