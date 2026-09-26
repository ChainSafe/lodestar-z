import {expect, test, vi} from "vitest";
import {type NativeIncomingRequest, initializeNativeNetworkRuntime} from "../src/network.js";
import {applicationConfig, capacity, localIntent, settleOnly, unreachableConnect} from "./utils/network.js";
import {BLOCKS} from "./utils/network-incoming.js";
import {startPeer} from "./utils/network-peer.js";

// Fails the next `failures` serving facades the wrapper constructs, as a programming error there would.
const facades = vi.hoisted(() => ({failures: 0, injected: new Error("facade construction failed")}));
vi.mock("../src/network-incoming.js", async (original) => {
  const incoming = await original<typeof import("../src/network-incoming.js")>();
  class NativeIncoming extends incoming.NativeIncoming {
    constructor(...args: ConstructorParameters<typeof incoming.NativeIncoming>) {
      if (facades.failures > 0) {
        facades.failures--;
        throw facades.injected;
      }
      super(...args);
    }
  }
  // biome-ignore lint/style/useNamingConvention: the mock replaces the module's exported class.
  return {...incoming, NativeIncoming};
});

test("a serving start the binding cannot wrap is cancelled alone while the drain continues and close settles", async () => {
  const [leftConfig, rightConfig] = [applicationConfig(), applicationConfig()];
  rightConfig.identitySecretKey[31] = 2;
  const left = await startPeer(leftConfig);
  const served: NativeIncomingRequest[] = [];
  const turns: {more: boolean; failure: unknown}[] = [];
  let serving = 0;
  let scheduled = false;
  const schedule = () => {
    if (scheduled) return;
    scheduled = true;
    setImmediate(() => {
      scheduled = false;
      const result = right.exchange([], {...settleOnly, capacity, servingStarts: serving});
      turns.push({failure: result.failure, more: result.more});
      served.push(...result.serving);
      if (result.more) schedule();
      else if (result.disabledWaiting) setTimeout(schedule, 25).unref();
    });
  };
  const right = initializeNativeNetworkRuntime(rightConfig, schedule);
  try {
    const identity = await right.identity;
    await Promise.all([
      left.applyIntent(localIntent(leftConfig), leftConfig.initialSlot),
      right.applyIntent(localIntent(rightConfig), rightConfig.initialSlot),
    ]);
    await left.connect(identity.peerId, [identity.localEndpoint], 5000n);
    const outcomes = [0, 1].map(() =>
      left
        .request(identity.peerId, BLOCKS, new Uint8Array(32))
        .next()
        .then(
          () => "served",
          () => "cancelled"
        )
    );
    await expect.poll(() => right.diagnostics().incoming.queued).toBe(2);
    facades.failures = 1;
    serving = 8;
    schedule();
    await expect.poll(() => served.length + turns.filter(({failure}) => failure).length).toBe(2);
    const failed = turns.findIndex(({failure}) => failure === facades.injected);
    expect(turns[failed].more).toBe(true);
    await expect.poll(() => turns.length).toBeGreaterThan(failed + 1);
    expect(served).toHaveLength(1);
    await served[0].finish();
    expect((await Promise.all(outcomes)).sort()).toEqual(["cancelled", "served"]);
    expect(await right.close()).toEqual({reason: "requested"});
    expect(right.diagnostics().incoming.occupied).toBe(0);
  } finally {
    facades.failures = 0;
    await Promise.allSettled([left.close(), right.close()]);
  }
}, 20000);

/** Closes a runtime and settles its pending connect through the host's exchanges until closed. */
async function settleClosedConnect() {
  const runtime = initializeNativeNetworkRuntime(applicationConfig(), () => undefined);
  const connect = runtime.connect(...unreachableConnect()).catch((error: unknown) => error);
  let closed = false;
  void runtime.close().then(() => {
    closed = true;
  });
  for (let i = 0; i < 400 && !closed; i++) {
    await new Promise((resolve) => setTimeout(resolve, 5));
    runtime.exchange([], settleOnly);
  }
  return {closed, error: await connect, facade: new WeakRef(runtime)};
}

test("settled errors carry their code and keep no frames that retain the facade", async () => {
  const {closed, error, facade} = await settleClosedConnect();
  expect(closed).toBe(true);
  expect(error).toBeInstanceOf(Error);
  expect(Object.getOwnPropertyDescriptor(error, "code")?.value).toBe("NetworkClosed");
  expect(error).toMatchObject({message: "NetworkClosed", name: "Error", stack: "Error: NetworkClosed"});
  // Dereferencing keeps the target alive for the rest of the job, so each collection runs in a later one.
  for (let i = 0; i < 100; i++) {
    await new Promise((resolve) => setTimeout(resolve, 10));
    global.gc?.();
    if (!facade.deref()) break;
  }
  expect(facade.deref()).toBeUndefined();
});
