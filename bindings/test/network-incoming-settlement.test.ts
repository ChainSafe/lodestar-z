import {expect, test} from "vitest";
import {type NativeIncomingRequest, initializeNativeNetworkRuntime} from "../src/network.js";
import {applicationConfig, capacity, localIntent, settleOnly, unreachableConnect} from "./utils/network.js";
import {BLOCKS} from "./utils/network-incoming.js";
import {startPeer} from "./utils/network-peer.js";

/** Runs `run` while inherited `failure` accessors and array iteration throw, as a hostile realm could arrange. */
function trapped<T>(run: () => T): T {
  const iterator = Array.prototype[Symbol.iterator];
  const trap = () => {
    throw Error("inherited trap");
  };
  Object.defineProperty(Object.prototype, "failure", {configurable: true, get: trap, set: trap});
  Array.prototype[Symbol.iterator] = trap;
  try {
    return run();
  } finally {
    Array.prototype[Symbol.iterator] = iterator;
    Reflect.deleteProperty(Object.prototype, "failure");
  }
}

test("a serving start the binding cannot wrap is cancelled alone while the drain continues and close settles", async () => {
  const [leftConfig, rightConfig] = [applicationConfig(), applicationConfig()];
  rightConfig.identitySecretKey[31] = 2;
  const left = await startPeer(leftConfig);
  const served: NativeIncomingRequest[] = [];
  const turns: {more: boolean; failure: unknown}[] = [];
  let serving = 0;
  let hostile = false;
  let scheduled = false;
  const schedule = () => {
    if (scheduled) return;
    scheduled = true;
    setImmediate(() => {
      scheduled = false;
      const exchange = () => right.exchange([], {...settleOnly, capacity, servingStarts: serving});
      const {more, failure, serving: starts, disabledWaiting} = hostile ? trapped(exchange) : exchange();
      hostile = false;
      turns.push({failure, more});
      served.push(...starts);
      if (more) schedule();
      else if (disabledWaiting) setTimeout(schedule, 25).unref();
    });
  };
  const right = initializeNativeNetworkRuntime(rightConfig, schedule);
  // The binding registers each serving facade for finalization; the first registration fails.
  const registry = FinalizationRegistry.prototype as {register(...args: unknown[]): void};
  const register = registry.register;
  const injected = new Error("facade construction failed");
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
    registry.register = function (this: unknown, ...args: unknown[]) {
      if (!(args[1] instanceof Object && "route" in args[1])) return register.apply(this, args);
      registry.register = register;
      throw injected;
    };
    serving = 8;
    hostile = true;
    schedule();
    await expect.poll(() => served.length + turns.filter(({failure}) => failure).length).toBe(2);
    registry.register = register;
    const failed = turns.findIndex(({failure}) => failure === injected);
    expect(turns[failed].more).toBe(true);
    await expect.poll(() => turns.length).toBeGreaterThan(failed + 1);
    expect(served).toHaveLength(1);
    await served[0].finish();
    expect((await Promise.all(outcomes)).sort()).toEqual(["cancelled", "served"]);
    expect(await right.close()).toEqual({reason: "requested"});
    expect(right.diagnostics().incoming.occupied).toBe(0);
  } finally {
    registry.register = register;
    await Promise.allSettled([left.close(), right.close()]);
  }
}, 20000);

test("settlement leaves Error to the host and drops each settled error's stack", async () => {
  // Notifications schedule nothing, so completions wait for the test's exchanges.
  let notified = 0;
  const runtime = initializeNativeNetworkRuntime(applicationConfig(), () => {
    notified++;
  });
  const original = Error;
  const limit = Object.getOwnPropertyDescriptor(original, "stackTraceLimit");
  const seen: unknown[] = [];
  let closed = false;
  void runtime.closed.then(() => {
    closed = true;
  });
  const connect = runtime.connect(...unreachableConnect()).catch((error: unknown) => error);
  try {
    const identity = runtime.getIdentity();
    await expect.poll(() => notified).toBe(1);
    // Resolving the identity looks up its `then`: the getter sees the host's limit, freezes it and replaces Error.
    // biome-ignore lint/suspicious/noThenProperty: an inherited `then` getter is how settlement runs host code.
    Object.defineProperty(Object.prototype, "then", {
      configurable: true,
      get() {
        seen.push(original.stackTraceLimit);
        Object.defineProperty(original, "stackTraceLimit", {configurable: true, value: 7, writable: false});
        Object.defineProperty(globalThis, "Error", {configurable: true, value: class extends original {}});
        return undefined;
      },
    });
    let result: ReturnType<typeof runtime.exchange> | undefined;
    try {
      result = runtime.exchange([], settleOnly);
    } finally {
      Reflect.deleteProperty(Object.prototype, "then");
      Object.defineProperty(globalThis, "Error", {configurable: true, value: original});
    }
    expect(result).toMatchObject({failure: null, more: false});
    expect(seen).toEqual([limit?.value]);
    expect(original.stackTraceLimit).toBe(7);
    expect((await identity).peerId).toBe(runtime.identity.peerId);
  } finally {
    if (limit) Object.defineProperty(original, "stackTraceLimit", limit);
    void runtime.close();
    for (let i = 0; i < 400 && !closed; i++) {
      await new Promise((resolve) => setTimeout(resolve, 5));
      runtime.exchange([], settleOnly);
    }
  }
  expect(closed).toBe(true);
  expect(await connect).toMatchObject({code: "NetworkClosed", stack: "Error: NetworkClosed"});
});

/** Closes a runtime and settles its pending connect under an inherited `code` setter that installs a stack setter. */
async function settleUnderCodeSetter(setters: unknown[]) {
  const runtime = initializeNativeNetworkRuntime(applicationConfig(), () => undefined);
  const connect = runtime.connect(...unreachableConnect()).catch((error: unknown) => error);
  let closed = false;
  void runtime.close().then(() => {
    closed = true;
  });
  for (let i = 0; i < 400 && runtime.state !== "closed"; i++) await new Promise((resolve) => setTimeout(resolve, 5));
  Object.defineProperty(Error.prototype, "code", {
    configurable: true,
    set(this: object, value: unknown) {
      setters.push(value);
      Object.defineProperty(this, "stack", {configurable: true, set: () => setters.push("stack")});
    },
  });
  let settled = false;
  void connect.then(() => {
    settled = true;
  });
  try {
    runtime.exchange([], settleOnly);
  } finally {
    Reflect.deleteProperty(Error.prototype, "code");
  }
  // Nothing else settles here, so the connect settled in that exchange.
  await new Promise(setImmediate);
  for (let i = 0; i < 400 && !closed; i++) {
    await new Promise((resolve) => setTimeout(resolve, 5));
    runtime.exchange([], settleOnly);
  }
  return {error: await connect, facade: new WeakRef(runtime), settled};
}

test("settled errors run no inherited code setter and keep no frames that retain the facade", async () => {
  const setters: unknown[] = [];
  const {facade, error, settled} = await settleUnderCodeSetter(setters);
  expect(settled).toBe(true);
  expect(setters).toEqual([]);
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
