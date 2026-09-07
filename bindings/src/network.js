import bindings from "./bindings.js";

class NativeRuntime {
  #native;
  #closed;
  #onReadable;

  constructor(config, onReadable) {
    if (typeof onReadable !== "function") throw new Error("InvalidNetworkConfig");
    this.#native = new bindings.NativeNetworkRuntime();
    this.#onReadable = onReadable;
    const promises = this.#native.start(config, NativeRuntime.#notifier(new WeakRef(this)));
    this.ready = promises.ready;
    this.#closed = promises.closed;
  }

  static #notifier(weak) {
    return () => weak.deref()?.#onReadable();
  }

  get state() { return this.#native.getState(); }
  setCurrentSlot(slot) { return this.#native.setCurrentSlot(slot); }
  diagnostics() { return this.#native.diagnostics(); }
  drain(maxEvents) { return this.#native.drain(maxEvents); }
  close() {
    this.#native.close();
    return this.#closed;
  }
}

export function createNativeNetworkRuntime(config, onReadable) {
  return new NativeRuntime(config, onReadable);
}
