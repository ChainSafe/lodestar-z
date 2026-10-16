import {createNativeNetwork as createNetwork} from "../../src/network.js";
import bindings from "../../src/bindings.js";
import {NativeIncoming} from "../../src/network-incoming.js";
import {NativeRequest} from "../../src/network-request.js";

const live = new Set();

class NativeRuntime {
  #native;
  #closed;
  #latestIdentity;
  #peers = new Map();
  #directPeers = new Set();
  #stopping = false;
  #onPeers;

  constructor(config, onWorkAvailable, onPeers) {
    this.#onPeers = onPeers;
    this.#native = new bindings.NativeNetworkRuntime();
    const initialized = this.#native.initialize(config, onWorkAvailable);
    this.identity = structuredClone(initialized.identity);
    this.#latestIdentity = initialized.identity;
    this.limits = initialized.limits;
    this.#closed = initialized.closed;
    live.add(this);
    void this.#closed.then(() => live.delete(this));
  }

  get closed() {
    return this.#closed;
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
  async applyIntent(intent) {
    return this.#native.applyIntent(intent);
  }
  updateStatus(status) {
    return this.#native.updateStatus(status);
  }
  getIdentity() {
    if (this.#stopping) throw new Error("NetworkClosed");
    return Promise.resolve(structuredClone(this.#latestIdentity));
  }
  getPeers() {
    if (this.#stopping) throw new Error("NetworkClosed");
    const peers = [...this.#peers.values()];
    return Promise.resolve({peers, counts: {connected: peers.length, relevant: peers.filter((peer) => peer.relevant).length}});
  }
  getPeerScores() {
    return this.#native.getPeerScores();
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
    return this.#native.addDirectPeer(peerId, addresses).then(() => { this.#directPeers.add(peerId); });
  }
  removeDirectPeer(peerId) {
    return this.#native.removeDirectPeer(peerId).then((removed) => { this.#directPeers.delete(peerId); return removed; });
  }
  getDirectPeers() {
    if (this.#stopping) throw new Error("NetworkClosed");
    return Promise.resolve([...this.#directPeers]);
  }

  exchange() {
    const result = this.#native.exchange();
    if (result.identity) this.#latestIdentity = structuredClone(result.identity);
    this.#onPeers?.(result.peers);
    for (const event of result.peers) {
      if (event.type === "closed") this.#peers.delete(event.identity);
      else if (event.state.connection) this.#peers.set(event.state.identity, event.state);
      else this.#peers.delete(event.state.identity);
    }
    const serving = result.serving;
    if (serving.length === 0) return result;
    for (let i = 0; i < serving.length; i++) {
      const descriptor = serving[i];
      serving[i] = new NativeIncoming(this.#native, descriptor);
    }
    return result;
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
    this.#stopping = true;
    this.#native.close();
    return this.#closed;
  }
}

/** A low-level runtime, which its host drains through `exchange`. Private: for binding ownership tests. */
export function initializeNativeNetworkRuntime(config, onWorkAvailable, onPeers) {
  return new NativeRuntime(config, onWorkAvailable, onPeers);
}

export {createNetwork as createNativeNetwork};

/** Accesses the raw binding only in tests that inspect the public wrapper's native work. */
export function runtimeOf(network) {
  const key = Object.getOwnPropertySymbols(network).find((symbol) => symbol.description === "NativeNetwork.runtime");
  return key === undefined ? undefined : network[key];
}
