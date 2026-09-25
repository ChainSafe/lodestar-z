import bindings from "./bindings.js";
import {NativeIncoming} from "./network-incoming.js";
import {NativeRequest} from "./network-request.js";

class NativeRuntime {
  #native;
  #closed;
  #onWorkAvailable;
  #wake;

  constructor(config, onWorkAvailable) {
    this.#native = new bindings.NativeNetworkRuntime();
    this.#onWorkAvailable = onWorkAvailable;
    const weak = new WeakRef(this);
    this.#wake = NativeRuntime.#waker(weak);
    const callback = typeof onWorkAvailable === "function" ? NativeRuntime.#notifier(weak) : onWorkAvailable;
    const initialized = this.#native.initialize(config, callback);
    this.identity = initialized.identity;
    this.#closed = initialized.closed;
  }

  /** Reports whether a host took the notification; a collected wrapper leaves settlement to native. */
  static #notifier(weak) {
    return () => {
      const runtime = weak.deref();
      if (runtime === undefined) return false;
      runtime.#onWorkAvailable();
      return true;
    };
  }

  /** Schedules the host drain after a call that leaves results to settle. */
  static #waker(weak) {
    return () => {
      try {
        weak.deref()?.#onWorkAvailable();
      } catch {
        // The owner's notifications report a throwing host; the caller's operation stands.
      }
    };
  }

  get closed() {
    return this.#closed;
  }
  get state() {
    return this.#native.getState();
  }
  diagnostics() {
    return this.#native.diagnostics();
  }
  getMetrics() {
    return this.#native.getMetrics();
  }
  drainLogs(maxRecords = 32) {
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
  reportPeer(peerId, action) {
    return this.#native.reportPeer(peerId, action);
  }
  exchange(demand) {
    const result = this.#native.exchange(demand);
    // Native has committed every item, so nothing may throw from here. Only own properties native created are read
    // or written. A start without a facade is cancelled, released and reported with `more` set, so the host still
    // takes the rest and drains again.
    const serving = result.serving;
    let taken = 0;
    for (let i = 0; i < serving.length; i++) {
      const descriptor = serving[i];
      try {
        serving[taken] = new NativeIncoming(this.#native, descriptor, this.#wake);
        taken++;
      } catch (error) {
        try {
          this.#native.incomingTerminal(descriptor.handle, 2, undefined, undefined);
          this.#native.incomingRelease(descriptor.handle);
        } catch {
          // Runtime teardown also releases native serving capacity.
        }
        result.failure ??= error;
        result.more = true;
      }
    }
    serving.length = taken;
    return result;
  }
  classifyGossip(results) {
    return this.#native.classifyGossip(results);
  }
  notifyGossipBlock(root) {
    return this.#native.notifyGossipBlock(root);
  }
  trackGossipSearch(root, peer) {
    return this.#native.trackGossipSearch(root, peer);
  }
  dropQueuedGossip() {
    return this.#native.dropQueuedGossip();
  }
  reportGossip(handle, verdict) {
    return this.#native.reportGossip(handle, verdict);
  }
  async publishGossip(topic, data, options) {
    return this.#native.publishGossip(topic, data, options);
  }
  request(peerId, protocol, data, options) {
    return new NativeRequest(this.#native, this.#native.requestStart(peerId, protocol, data, options), this.#wake);
  }
  close() {
    this.#native.close();
    return this.#closed;
  }
}

export function initializeNativeNetworkRuntime(config, onWorkAvailable) {
  return new NativeRuntime(config, onWorkAvailable);
}
