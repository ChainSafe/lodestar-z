import {NativePump, closeResult} from "./network-pump.js";
import {NativeRuntime, initializeNativeNetworkRuntime, registerRuntime} from "./network-runtime.js";

export {initializeNativeNetworkRuntime};

const HOST_METHODS = ["capacity", "validate", "checkDependencies", "serve", "peers", "failed", "logs"];
const CONNECT_TIMEOUT_MS = 10000n;

class NativeNetwork {
  #runtime;
  #pump;

  constructor(config, host) {
    for (const name of HOST_METHODS)
      if (typeof host?.[name] !== "function") throw new TypeError(`NativeHost.${name} must be a function`);
    const terminal = {failure: null};
    const pump = new NativePump(host, terminal);
    const runtime = new NativeRuntime(config, pump.request);
    pump.attach(runtime);
    this.#runtime = runtime;
    this.#pump = pump;
    this.limits = Object.freeze({...runtime.limits});
    this.closed = closeResult(runtime.closed, terminal);
    registerRuntime(this, runtime);
  }

  applyIntent(intent, slot) {
    return this.#runtime.applyIntent(intent, slot);
  }
  updateStatus(status) {
    return this.#runtime.updateStatus(status);
  }
  blockImported(root) {
    this.#pump.block(root);
  }
  reportPeer(peerId, action) {
    this.#pump.reportPeer(peerId, action);
  }
  dropQueuedGossip() {
    this.#pump.dropQueued();
  }
  notifyCapacity() {
    this.#pump.request();
  }
  publish(topic, data, options) {
    return this.#runtime.publishGossip(topic, data, options);
  }
  request(peerId, protocol, data, options) {
    return this.#runtime.request(peerId, protocol, data, options);
  }
  connect(peerId, endpoints, timeoutMs = CONNECT_TIMEOUT_MS) {
    return this.#runtime.connect(peerId, endpoints, timeoutMs);
  }
  disconnect(peerId) {
    return this.#runtime.disconnect(peerId);
  }
  setDirectPeer(peerId, endpoints) {
    return endpoints === null ? this.#runtime.removeDirectPeer(peerId) : this.#runtime.addDirectPeer(peerId, endpoints);
  }
  reStatus(peerIds) {
    return this.#runtime.reStatusPeers(peerIds);
  }
  getIdentity() {
    return this.#runtime.getIdentity();
  }
  getPeers() {
    return this.#runtime.getPeers();
  }
  getDirectPeers() {
    return this.#runtime.getDirectPeers();
  }
  getGossipDiagnostics(cursor) {
    return this.#runtime.getGossipDiagnostics(cursor);
  }
  getRememberedPeers() {
    return this.#runtime.getRememberedPeers();
  }
  metrics() {
    return this.#runtime.getMetrics() + this.#pump.metrics();
  }
  setLogLevel(level) {
    this.#runtime.setLogLevel(level);
  }
  close() {
    this.#pump.close();
    this.#runtime.close();
    return this.closed;
  }
}

/**
 * Starts a runtime whose binding-owned pump drives `host`. Invokes no host callback synchronously; the first turn
 * follows the first native notification.
 */
export function createNativeNetwork(config, host) {
  return new NativeNetwork(config, host);
}
