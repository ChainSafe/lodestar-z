import bindings from "./bindings.js";
import {IncomingRecord, NativeIncoming} from "./network-incoming.js";
import {NativeRequest, RequestRecord} from "./network-request.js";
import {CompletionOwner} from "./network-tickets.js";

export class NativeRuntime {
  #native;
  #owner;
  #closed;

  constructor(config, onWorkAvailable) {
    this.#native = new bindings.NativeNetworkRuntime();
    const owner = new CompletionOwner(this.#native);
    const initialized = this.#native.initialize(config, onWorkAvailable);
    owner.size(initialized.capacities);
    this.#owner = owner;
    this.identity = initialized.identity;
    this.limits = initialized.limits;
    this.#closed = owner.closed;
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
    return this.#command("applyIntent", () => this.#native.applyIntent(intent, slot));
  }
  updateStatus(status) {
    return this.#command("updateStatus", () => this.#native.updateStatus(status));
  }
  getIdentity() {
    return this.#command("getIdentity", () => this.#native.getIdentity());
  }
  getPeers() {
    return this.#command("getPeers", () => this.#native.getPeers());
  }
  getGossipDiagnostics(cursor = 0) {
    return this.#command("getGossipDiagnostics", () => this.#native.getGossipDiagnostics(cursor));
  }
  connect(peerId, addresses, timeoutMs) {
    return this.#command("connect", () => this.#native.connect(peerId, addresses, timeoutMs));
  }
  disconnect(peerId) {
    return this.#command("disconnect", () => this.#native.disconnect(peerId));
  }
  reStatusPeers(peerIds) {
    return this.#command("reStatusPeers", () => this.#native.reStatusPeers(peerIds));
  }
  addDirectPeer(peerId, addresses) {
    return this.#command("addDirectPeer", () => this.#native.addDirectPeer(peerId, addresses));
  }
  removeDirectPeer(peerId) {
    return this.#command("removeDirectPeer", () => this.#native.removeDirectPeer(peerId));
  }
  getDirectPeers() {
    return this.#command("getDirectPeers", () => this.#native.getDirectPeers());
  }
  getRememberedPeers() {
    return this.#command("getRememberedPeers", () => this.#native.getRememberedPeers());
  }
  /** Admits one command of `kind`, whose completion must name that kind. Refusal throws, as the native call does. */
  #command(kind, submit) {
    return this.#owner.admit("command", kind, submit);
  }
  exchange(actions, demand) {
    const result = this.#owner.exchange(actions, demand);
    // An exchange that delivered nothing is frozen with no serving starts.
    const serving = result.serving;
    if (serving.length === 0) return result;
    for (let i = 0; i < serving.length; i++) {
      const descriptor = serving[i];
      const record = new IncomingRecord(this.#native, descriptor.handle);
      this.#owner.serve(record);
      serving[i] = new NativeIncoming(descriptor, record);
    }
    return result;
  }
  fail(site, reason) {
    return this.#native.fail(site, reason);
  }
  checkAction(action) {
    this.#native.checkAction(action);
  }
  holdVerdicts(held) {
    this.#native.holdVerdicts(held);
  }
  holdOperations(held) {
    this.#native.holdOperations(held);
  }
  async publishGossip(topic, data, options) {
    return this.#owner.admit("publication", undefined, () => this.#native.publishGossip(topic, data, options));
  }
  request(peerId, protocol, data, options) {
    const record = new RequestRecord();
    const handle = this.#owner.request(record, () => this.#native.requestStart(peerId, protocol, data, options));
    return new NativeRequest(this.#native, handle, record);
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
