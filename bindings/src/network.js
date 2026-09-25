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
  reportPeer(peerId, action) {
    return this.#native.reportPeer(peerId, action);
  }
  exchange(demand) {
    // Settled errors describe native outcomes. A captured drain frame would only keep this wrapper alive.
    const stackTraceLimit = Error.stackTraceLimit;
    Error.stackTraceLimit = 0;
    let result;
    try {
      result = this.#native.exchange(demand);
    } finally {
      Error.stackTraceLimit = stackTraceLimit;
    }
    // Native has committed every item, so nothing may throw from here: a start without a facade is cancelled and
    // released, and the result reports it with `more` set, so the host still takes the rest and drains again.
    const serving = result.serving;
    let taken = 0;
    for (const descriptor of serving) {
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
