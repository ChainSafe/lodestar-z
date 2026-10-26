import bindings from "./bindings.js";
import {RequestCapacityWaiters} from "./network-capacity.js";
import {NativePump} from "./network-pump.js";
import {NativeRequest} from "./network-request.js";

const openNetworks = new Set();
const NATIVE = Symbol("NativeNetwork.runtime");

const HOST_METHODS = [
  "capacity",
  "subscribeCapacity",
  "validate",
  "checkDependencies",
  "serve",
  "peers",
  "failed",
  "logs",
];
const CONNECT_TIMEOUT_MS = 10000n;

class NativeNetwork {
  #native;
  #pump;
  #requestCapacity;
  #metricsPending = null;
  #identity;
  #directPeers = new Set();
  #directPending = Promise.resolve();
  #closing = false;

  constructor(config, host) {
    for (const name of HOST_METHODS)
      if (typeof host?.[name] !== "function") throw new TypeError(`NativeHost.${name} must be a function`);
    const pump = new NativePump(
      host,
      (identity) => {
        this.#identity = identity;
      },
      () => {
        this.#requestCapacity.changed();
        host.requestCapacityChanged?.();
      }
    );
    const native = new bindings.NativeNetworkRuntime();
    const initialized = native.initialize(config, pump.request);
    this.#native = native;
    this.#requestCapacity = new RequestCapacityWaiters(native);
    this.#identity = initialized.identity;
    Object.defineProperty(this, NATIVE, {value: native});
    pump.attach(native, initialized.closed);
    this.#pump = pump;
    this.limits = Object.freeze({...initialized.limits});
    this.closed = initialized.closed;
    openNetworks.add(this);
    void this.closed.then(() => {
      this.#requestCapacity.close();
      this.#closing = true;
      openNetworks.delete(this);
    });
  }

  async applyIntent(intent) {
    return this.#native.applyIntent(intent);
  }
  async updateStatus(status) {
    return this.#native.updateStatus(status);
  }
  blockImported(root) {
    this.#native.notifyBlock(root);
  }
  reportPeer(peerId, action, context) {
    this.#native.reportPeer(peerId, action, context);
  }
  dropQueuedGossip() {
    this.#native.dropQueuedGossip();
  }
  stopDelivery() {
    this.#pump.stopDelivery();
  }
  async publish(topic, data, options) {
    return this.#native.publishGossip(topic, data, options);
  }
  request(peerId, protocol, data, options) {
    return new NativeRequest(this.#native, this.#native.requestStart(peerId, protocol, data, options));
  }
  waitForRequestCapacity(token, options) {
    return this.#requestCapacity.wait(token, options);
  }
  watchRequestCapacity(token) {
    return this.#native.requestCapacityWatch(token);
  }
  async connect(peerId, endpoints, timeoutMs = CONNECT_TIMEOUT_MS) {
    return this.#native.connect(peerId, endpoints, timeoutMs);
  }
  async disconnect(peerId) {
    return this.#native.disconnect(peerId);
  }
  async setDirectPeer(peerId, endpoints) {
    const operation =
      endpoints === null ? this.#native.removeDirectPeer(peerId) : this.#native.addDirectPeer(peerId, endpoints);
    // Native completions need not settle in submission order. Apply membership changes in that order.
    const outcome = operation.then(
      (value) => ({value}),
      (error) => ({error})
    );
    const applied = this.#directPending.then(async () => {
      const result = await outcome;
      if ("error" in result) throw result.error;
      if (endpoints === null) this.#directPeers.delete(peerId);
      else this.#directPeers.add(peerId);
      return result.value;
    });
    this.#directPending = applied.then(
      () => undefined,
      () => undefined
    );
    return applied;
  }
  async reStatus(peerIds) {
    return this.#native.reStatusPeers(peerIds);
  }
  async getIdentity() {
    this.#checkOpen();
    return structuredClone(this.#identity);
  }
  async getDirectPeers() {
    this.#checkOpen();
    return [...this.#directPeers];
  }
  async getPeerScores() {
    return this.#native.getPeerScores();
  }
  async getGossipDiagnostics(cursor = 0) {
    return this.#native.getGossipDiagnostics(cursor);
  }

  metrics() {
    this.#metricsPending ??= this.#collectMetrics().finally(() => {
      this.#metricsPending = null;
    });
    return this.#metricsPending;
  }
  async #collectMetrics() {
    this.#checkOpen();
    return (await this.#native.getMetrics()) + this.#pump.metrics();
  }
  setLogLevel(level) {
    this.#native.setLogLevel(level);
  }
  #checkOpen() {
    if (this.#closing) throw Object.assign(new Error("NetworkClosed"), {code: "NetworkClosed"});
  }
  close() {
    this.#closing = true;
    this.#requestCapacity.close();
    this.#pump.stopDelivery();
    this.#native.close();
    return this.closed;
  }
}

/**
 * Keeps the wrapper and event loop alive until close. The binding-owned pump invokes no host callback
 * synchronously; its first turn subscribes to host capacity and reads its initial value.
 */
export function createNativeNetwork(config, host) {
  return new NativeNetwork(config, host);
}
