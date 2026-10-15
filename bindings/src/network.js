import bindings from "./bindings.js";
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
  #metricsPending = null;

  constructor(config, host) {
    for (const name of HOST_METHODS)
      if (typeof host?.[name] !== "function") throw new TypeError(`NativeHost.${name} must be a function`);
    const pump = new NativePump(host);
    const native = new bindings.NativeNetworkRuntime();
    const initialized = native.initialize(config, pump.request);
    this.#native = native;
    Object.defineProperty(this, NATIVE, {value: native});
    pump.attach(native, initialized.closed);
    this.#pump = pump;
    this.limits = Object.freeze({...initialized.limits});
    this.closed = initialized.closed;
    openNetworks.add(this);
    void this.closed.then(() => openNetworks.delete(this));
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
  async connect(peerId, endpoints, timeoutMs = CONNECT_TIMEOUT_MS) {
    return this.#native.connect(peerId, endpoints, timeoutMs);
  }
  async disconnect(peerId) {
    return this.#native.disconnect(peerId);
  }
  async setDirectPeer(peerId, endpoints) {
    return endpoints === null ? this.#native.removeDirectPeer(peerId) : this.#native.addDirectPeer(peerId, endpoints);
  }
  async reStatus(peerIds) {
    return this.#native.reStatusPeers(peerIds);
  }
  async getIdentity() {
    return this.#native.getIdentity();
  }
  async getPeers() {
    return this.#native.getPeers();
  }
  async getDirectPeers() {
    return this.#native.getDirectPeers();
  }
  async getGossipDiagnostics(cursor = 0) {
    return this.#native.getGossipDiagnostics(cursor);
  }
  async getRememberedPeers() {
    return this.#native.getRememberedPeers();
  }
  metrics() {
    this.#metricsPending ??= this.#collectMetrics().finally(() => {
      this.#metricsPending = null;
    });
    return this.#metricsPending;
  }
  async #collectMetrics() {
    return (await this.#native.getMetrics()) + this.#pump.metrics();
  }
  setLogLevel(level) {
    this.#native.setLogLevel(level);
  }
  close() {
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
