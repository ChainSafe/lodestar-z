import bindings from "./bindings.js";
import {NativeIncoming} from "./network-incoming.js";
import {NativeRequest} from "./network-request.js";

export class NativeRuntime {
  #native;
  #closed;

  constructor(config, onWorkAvailable) {
    this.#native = new bindings.NativeNetworkRuntime();
    const initialized = this.#native.initialize(config, onWorkAvailable);
    this.identity = initialized.identity;
    this.limits = initialized.limits;
    this.#closed = initialized.closed;
  }

  get closed() {
    return this.#closed;
  }
  get state() {
    return this.#native.getState();
  }
  getMetrics() {
    return this.#native.getMetrics();
  }
  drainLogs(maxRecords = 256) {
    return this.#native.drainLogs(maxRecords);
  }
  setLogLevel(level) {
    this.#native.setLogLevel(level);
  }
  async applyIntent(intent, slot) {
    return this.#native.applyIntent(intent, slot);
  }
  updateStatus(status) {
    return this.#native.updateStatus(status);
  }
  getIdentity() {
    return this.#native.getIdentity();
  }
  getPeers() {
    return this.#native.getPeers();
  }
  getGossipDiagnostics(cursor = 0) {
    return this.#native.getGossipDiagnostics(cursor);
  }
  connect(peerId, addresses, timeoutMs) {
    return this.#native.connect(peerId, addresses, timeoutMs);
  }
  disconnect(peerId) {
    return this.#native.disconnect(peerId);
  }
  reStatusPeers(peerIds) {
    return this.#native.reStatusPeers(peerIds);
  }
  addDirectPeer(peerId, addresses) {
    return this.#native.addDirectPeer(peerId, addresses);
  }
  removeDirectPeer(peerId) {
    return this.#native.removeDirectPeer(peerId);
  }
  getDirectPeers() {
    return this.#native.getDirectPeers();
  }
  getRememberedPeers() {
    return this.#native.getRememberedPeers();
  }
  exchange() {
    const result = this.#native.exchange();
    // An exchange that delivered nothing is frozen with no serving starts.
    const serving = result.serving;
    if (serving.length === 0) return result;
    for (let i = 0; i < serving.length; i++) {
      const descriptor = serving[i];
      serving[i] = new NativeIncoming(this.#native, descriptor);
    }
    return result;
  }
  drainCompletions() {
    return this.#native.drainCompletions();
  }
  reportFailure(error) {
    return this.#native.reportFailure(error);
  }
  setCapacity(capacity) {
    this.#native.setCapacity(capacity);
  }
  reportGossip(handle, verdict) {
    this.#native.reportGossip(handle, verdict);
  }
  classifyGossip(handle, available) {
    this.#native.classifyGossip(handle, available);
  }
  notifyBlock(root) {
    this.#native.notifyBlock(root);
  }
  dropQueuedGossip() {
    this.#native.dropQueuedGossip();
  }
  reportPeer(peerId, action, context) {
    this.#native.reportPeer(peerId, action, context);
  }
  holdVerdicts(held) {
    this.#native.holdVerdicts(held);
  }
  holdOperations(held) {
    this.#native.holdOperations(held);
  }
  async publishGossip(topic, data, options) {
    return this.#native.publishGossip(topic, data, options);
  }
  request(peerId, protocol, data, options) {
    return new NativeRequest(this.#native, this.#native.requestStart(peerId, protocol, data, options));
  }
  close() {
    this.#native.close();
    return this.#closed;
  }
}

/** A low-level runtime, which its host drains through `exchange`. Private: for binding ownership tests. */
export function initializeNativeNetworkRuntime(config, onWorkAvailable) {
  return new NativeRuntime(config, onWorkAvailable);
}

/** Each facade's runtime, for binding ownership tests. */
const runtimes = new WeakMap();
export function registerRuntime(network, runtime) {
  runtimes.set(network, runtime);
}
export function runtimeOf(network) {
  return runtimes.get(network);
}
