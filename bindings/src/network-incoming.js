const finalizers = new FinalizationRegistry(({route, handle}) => {
  try { route.deref()?.incomingTerminal(handle, 2, undefined, undefined); } catch {}
});

function failure(code) {
  return Object.assign(new Error(code), {code});
}

export class NativeIncoming {
  #route;
  #handle;
  #done = false;
  #terminal = false;

  constructor(native, descriptor) {
    this.#route = new WeakRef(native);
    this.#handle = descriptor.handle;
    this.peerId = descriptor.peerId;
    this.connection = descriptor.connection;
    this.protocol = descriptor.protocol;
    this.data = descriptor.data;
    this.closed = descriptor.closed;
    const weak = new WeakRef(this);
    this.closed.then(() => {
      const incoming = weak.deref();
      if (incoming) {
        incoming.#done = true;
        finalizers.unregister(incoming);
      }
    });
    finalizers.register(this, {route: this.#route, handle: this.#handle}, this);
  }

  respond(data, context) {
    if (this.#done || this.#terminal) return Promise.reject(failure("NetworkIncomingClosed"));
    const native = this.#route.deref();
    if (!native) return Promise.reject(failure("NetworkClosed"));
    try { return native.incomingRespond(this.#handle, data, context); }
    catch (error) { return Promise.reject(error); }
  }

  #end(action, status, message) {
    if (this.#done || (this.#terminal && action !== 2)) return this.closed;
    try {
      this.#route.deref()?.incomingTerminal(this.#handle, action, status, message);
      this.#terminal = true;
      return this.closed;
    } catch (error) {
      if (error.code === "NetworkIncomingClosed") return this.closed;
      return Promise.reject(error);
    }
  }

  finish() { return this.#end(0); }
  fail(status, message) { return this.#end(1, status, message); }
  cancel() { return this.#end(2); }
}
