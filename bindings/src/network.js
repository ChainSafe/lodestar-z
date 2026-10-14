import {NativePump} from "./network-pump.js";
import {NativeRuntime, registerRuntime} from "./network-runtime.js";

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
  #runtime;
  #pump;

  constructor(config, host) {
    for (const name of HOST_METHODS)
      if (typeof host?.[name] !== "function") throw new TypeError(`NativeHost.${name} must be a function`);
    const pump = new NativePump(host);
    const runtime = new NativeRuntime(config, pump.request);
    pump.attach(runtime);
    this.#runtime = runtime;
    this.#pump = pump;
    this.limits = Object.freeze({...runtime.limits});
    this.closed = runtime.closed;
    registerRuntime(this, runtime);
  }

  async applyIntent(intent, slot) {
    return this.#runtime.applyIntent(intent, slot);
  }
  async updateStatus(status) {
    return this.#runtime.updateStatus(status);
  }
  blockImported(root) {
    this.#runtime.notifyBlock(root);
  }
  reportPeer(peerId, action, context) {
    this.#runtime.reportPeer(peerId, action, context);
  }
  dropQueuedGossip() {
    this.#runtime.dropQueuedGossip();
  }
  stopDelivery() {
    this.#pump.stopDelivery();
  }
  async publish(topic, data, options) {
    return this.#runtime.publishGossip(topic, data, options);
  }
  request(peerId, protocol, data, options) {
    return this.#runtime.request(peerId, protocol, data, options);
  }
  async connect(peerId, endpoints, timeoutMs = CONNECT_TIMEOUT_MS) {
    return this.#runtime.connect(peerId, endpoints, timeoutMs);
  }
  async disconnect(peerId) {
    return this.#runtime.disconnect(peerId);
  }
  async setDirectPeer(peerId, endpoints) {
    return endpoints === null ? this.#runtime.removeDirectPeer(peerId) : this.#runtime.addDirectPeer(peerId, endpoints);
  }
  async reStatus(peerIds) {
    return this.#runtime.reStatusPeers(peerIds);
  }
  async getIdentity() {
    return this.#runtime.getIdentity();
  }
  async getPeers() {
    return this.#runtime.getPeers();
  }
  async getDirectPeers() {
    return this.#runtime.getDirectPeers();
  }
  async getGossipDiagnostics(cursor) {
    return this.#runtime.getGossipDiagnostics(cursor);
  }
  async getRememberedPeers() {
    return this.#runtime.getRememberedPeers();
  }
  metrics() {
    return this.#runtime.getMetrics() + this.#pump.metrics();
  }
  setLogLevel(level) {
    this.#runtime.setLogLevel(level);
  }
  close() {
    this.#pump.stopDelivery();
    this.#runtime.close();
    return this.closed;
  }
}

/**
 * Starts a runtime whose binding-owned pump drives `host`. Invokes no host callback synchronously; the first turn
 * subscribes to host capacity and reads its initial value.
 */
export function createNativeNetwork(config, host) {
  return new NativeNetwork(config, host);
}
