import {Worker} from "node:worker_threads";
import {computeDomain} from "@lodestar/state-transition";
import {ssz} from "@lodestar/types";
import {describe, expect, it} from "vitest";
import {SecretKey} from "../src/blst.js";
import bindings from "../src/index.js";
import {createStfState, stfConfig} from "./stfFixture.js";

const bindingsPath = new URL("../src/index.js", import.meta.url).href;
const fixturePath = new URL("./stfFixture.ts", import.meta.url).href;

function createState() {
  bindings.config.set(stfConfig, new Uint8Array(32));
  bindings.pubkeys.ensureCapacity(16);
  const bytes = ssz.fulu.BeaconState.serialize(createStfState());
  return {bytes, state: bindings.BeaconStateView.createFromBytes(bytes)};
}

function signedExit() {
  const seed = new Uint8Array(32);
  seed[0] = 1;
  const message = {epoch: stfConfig.FULU_FORK_EPOCH, validatorIndex: 0};
  const domain = computeDomain(new Uint8Array([4, 0, 0, 0]), stfConfig.CAPELLA_FORK_VERSION, new Uint8Array(32));
  const signingRoot = ssz.phase0.SigningData.hashTreeRoot({
    domain,
    objectRoot: ssz.phase0.VoluntaryExit.hashTreeRoot(message),
  });
  return {message, signature: SecretKey.fromKeygen(seed).sign(signingRoot).toBytes()};
}

describe("state environment ownership", () => {
  it("binds setup handles to their configuration independently of later setup", () => {
    const first = new bindings.StateTransition(stfConfig, new Uint8Array(32));
    const second = new bindings.StateTransition(stfConfig, new Uint8Array(32).fill(1));
    bindings.pubkeys.ensureCapacity(16);
    const bytes = ssz.fulu.BeaconState.serialize(createStfState());
    expect(second.createFromBytes(bytes).getVoluntaryExitValidity(signedExit(), true)).toBe("invalid_signature");
    expect(first.createFromBytes(bytes).getVoluntaryExitValidity(signedExit(), true)).toBe("valid");
  });

  it("retains the original config for existing states and descendants after reconfiguration", () => {
    const {bytes, state} = createState();
    const exit = signedExit();
    expect(state.getVoluntaryExitValidity(exit, true)).toBe("valid");
    bindings.config.set({...stfConfig, FULU_FORK_EPOCH: Infinity}, new Uint8Array(32).fill(1));

    expect(state.getVoluntaryExitValidity(exit, true)).toBe("valid");
    const loaded = state.loadOtherState(bytes);
    const advanced = state.processSlots(state.slot + 1);
    expect(loaded.forkSeq).toBe(6);
    expect(advanced.forkSeq).toBe(6);
    expect(loaded.getVoluntaryExitValidity(exit, true)).toBe("valid");
    expect(advanced.getVoluntaryExitValidity(exit, true)).toBe("valid");
  });

  it("keeps state configuration alive after its setup handle is collected", async () => {
    bindings.pubkeys.ensureCapacity(16);
    const state = new bindings.StateTransition(stfConfig, new Uint8Array(32)).createFromBytes(
      ssz.fulu.BeaconState.serialize(createStfState())
    );
    global.gc?.();
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(state.getVoluntaryExitValidity(signedExit(), true)).toBe("valid");
    expect(state.processSlots(state.slot + 1).getVoluntaryExitValidity(signedExit(), true)).toBe("valid");
  });

  it("keeps the current config intact when parsing fails", () => {
    const {bytes} = createState();
    expect(() => bindings.config.set({...stfConfig, BLOB_SCHEDULE: [{}]}, new Uint8Array(32))).toThrow();
    const state = bindings.BeaconStateView.createFromBytes(bytes);
    expect(state.getVoluntaryExitValidity(signedExit(), true)).toBe("valid");
  });

  it("rejects a runtime preset that differs from the compiled preset", () => {
    expect(() => bindings.config.set({...stfConfig, PRESET_BASE: "minimal"}, new Uint8Array(32))).toThrow(
      "PresetMismatch"
    );
  });

  it.each([0, 6001])("rejects unrepresentable slot duration %s", (duration) => {
    const config = {...stfConfig, SECONDS_PER_SLOT: 12, SLOT_DURATION_MS: duration};
    expect(() => new bindings.StateTransition(config, new Uint8Array(32))).toThrow("InvalidSlotDuration");
  });

  it("isolates worker configuration and metrics from the main environment", async () => {
    const {state} = createState();
    bindings.metrics.init();
    const metrics = bindings.metrics.scrapeMetrics();
    const expectedRoot = state.processSlots(state.slot + 1).hashTreeRoot();
    const beforeWorker = bindings.metrics.scrapeMetrics();
    const root = await runWorker<Uint8Array>(`
      bindings.config.set(stfConfig, new Uint8Array(32));
      bindings.metrics.init();
      const state = bindings.BeaconStateView.createFromBytes(ssz.fulu.BeaconState.serialize(createStfState()));
      const root = state.processSlots(state.slot + 1).hashTreeRoot();
      bindings.config.set({...stfConfig, FULU_FORK_EPOCH: Infinity}, new Uint8Array(32).fill(1));
      parentPort.postMessage(root);
    `);
    expect(root).toEqual(expectedRoot);
    expect(bindings.metrics.scrapeMetrics()).toBe(beforeWorker);
    expect(state.getVoluntaryExitValidity(signedExit(), true)).toBe("valid");
    expect(state.processSlots(state.slot + 1).hashTreeRoot()).toEqual(expectedRoot);
    expect(metrics).toContain("stfn_epoch_transition");
  });

  it("runs simultaneous epoch transitions in independent workers", async () => {
    const {state} = createState();
    const expectedRoot = state.processSlots(state.slot + 1).hashTreeRoot();
    const roots = await Promise.all(
      Array.from({length: 3}, () =>
        runWorker<Uint8Array>(`
      bindings.config.set(stfConfig, new Uint8Array(32));
      const state = bindings.BeaconStateView.createFromBytes(ssz.fulu.BeaconState.serialize(createStfState()));
      let root;
      for (let i = 0; i < 8; i++) root = state.processSlots(state.slot + 1).hashTreeRoot();
      parentPort.postMessage(root);
    `)
      )
    );
    for (const [index, root] of roots.entries()) {
      expect(root, `worker ${index}`).toEqual(expectedRoot);
    }
  });

  it("allocates an independent bounded tree pool for each worker", async () => {
    const {state} = createState();
    const previousCapacity = process.env.LODESTAR_Z_NODE_POOL_CAPACITY;
    process.env.LODESTAR_Z_NODE_POOL_CAPACITY = "0";
    try {
      const code = await runWorker<string>(`
        bindings.config.set(stfConfig, new Uint8Array(32));
        try {
          bindings.BeaconStateView.createFromBytes(ssz.fulu.BeaconState.serialize(createStfState()));
          parentPort.postMessage("created");
        } catch (error) {
          parentPort.postMessage(error.code);
        }
      `);
      expect(code).toBe("PoolExhausted");
      expect(state.processSlots(state.slot + 1).slot).toBe(state.slot + 1);
    } finally {
      if (previousCapacity === undefined) {
        Reflect.deleteProperty(process.env, "LODESTAR_Z_NODE_POOL_CAPACITY");
      } else {
        process.env.LODESTAR_Z_NODE_POOL_CAPACITY = previousCapacity;
      }
    }
  });

  it("uses a distinct historical metrics prefix", async () => {
    const metrics = await runWorker<string>(`
      bindings.metrics.init({historical: true});
      bindings.metrics.init({historical: true});
      parentPort.postMessage(bindings.metrics.scrapeMetrics());
    `);
    expect(metrics).toContain("lodestar_historical_state_stfn_epoch_transition_seconds");
    expect(metrics).not.toContain("\nlodestar_stfn_");
  });

  it("rejects a changed metrics prefix after initialization", () => {
    bindings.metrics.init();
    expect(() => bindings.metrics.init({historical: true})).toThrow("MetricsAlreadyInitialized");
  });
});

function runWorker<T>(source: string): Promise<T> {
  return new Promise((resolve, reject) => {
    let result: T;
    const worker = new Worker(
      `
      import {parentPort} from "node:worker_threads";
      import {ssz} from "@lodestar/types";
      import bindings from ${JSON.stringify(bindingsPath)};
      import {createStfState, stfConfig} from ${JSON.stringify(fixturePath)};
      ${source}
    `,
      {eval: true}
    );
    worker.on("message", (message: T) => {
      result = message;
    });
    worker.on("error", reject);
    worker.on("exit", (code) => (code === 0 ? resolve(result) : reject(new Error(`Worker exited with code ${code}`))));
  });
}
