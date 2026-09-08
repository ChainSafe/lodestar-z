import bindings from "./bindings.js";
import {NativeIncoming} from "./network-incoming.js";
import {NativeRequest} from "./network-request.js";

class NativeRuntime {
  #native;
  #closed;
  #onReadable;

  constructor(config, onReadable, application = false) {
    if (typeof onReadable !== "function") throw new Error("InvalidNetworkConfig");
    this.#native = new bindings.NativeNetworkRuntime();
    this.#onReadable = onReadable;
    const promises = this.#native[application ? "prepare" : "start"](config, NativeRuntime.#notifier(new WeakRef(this)));
    if (!application) this.setCurrentSlot = (slot) => this.#native.setCurrentSlot(slot);
    if (application) {
      this.drainGossip = () => this.#native.drainGossip();
      this.reportGossip = (handle, verdict) => this.#native.reportGossip(handle, verdict);
      this.publishGossip = (topic, data, options) => this.#native.publishGossip(topic, data, options);
      this.takeIncomingRequest = () => {
        const descriptor = this.#native.takeIncomingRequest();
        if (descriptor === null) return null;
        try { return new NativeIncoming(this.#native, descriptor); }
        catch (error) {
          this.#native.incomingTerminal(descriptor.handle, 2, undefined, undefined);
          throw error;
        }
      };
    }
    this.ready = promises.ready;
    this.#closed = promises.closed;
  }

  static #notifier(weak) {
    return () => weak.deref()?.#onReadable();
  }

  get closed() { return this.#closed; }
  get state() { return this.#native.getState(); }
  diagnostics() { return this.#native.diagnostics(); }
  drain(maxEvents) { return this.#native.drain(maxEvents); }
  applyIntent(intent, slot) { return this.#native.applyIntent(intent, slot); }
  getIdentity() { return this.#native.getIdentity(); }
  getPeers() { return this.#native.getPeers(); }
  connect(peerId, addresses, timeoutMs) { return this.#native.connect(peerId, addresses, timeoutMs); }
  disconnect(peerId) { return this.#native.disconnect(peerId); }
  reStatusPeers(peerIds) { return this.#native.reStatusPeers(peerIds); }
  addDirectPeer(peerId, addresses) { return this.#native.addDirectPeer(peerId, addresses); }
  removeDirectPeer(peerId) { return this.#native.removeDirectPeer(peerId); }
  getDirectPeers() { return this.#native.getDirectPeers(); }
  reportPeer(peerId, action) { return this.#native.reportPeer(peerId, action); }
  drainPeers(maxEvents) { return this.#native.drainPeers(maxEvents); }
  request(peerId, protocol, data, options) {
    return new NativeRequest(this.#native, this.#native.requestStart(peerId, protocol, data, options));
  }
  close() {
    this.#native.close();
    return this.#closed;
  }
}

export function createNativeNetworkRuntime(config, onReadable) {
  return new NativeRuntime(config, onReadable);
}

export function createNativeNetworkApplicationRuntime(config, onReadable) {
  return new NativeRuntime(config, onReadable, true);
}
