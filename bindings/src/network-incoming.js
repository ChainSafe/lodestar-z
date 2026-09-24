const finalizers = new FinalizationRegistry(({route, handle}) => {
  try {
    route.deref()?.incomingTerminal(handle, 2, undefined, undefined);
    route.deref()?.incomingRelease(handle);
  } catch {
    // Runtime teardown may have already retired this handle.
  }
});

function failure(code) {
  return Object.assign(new Error(code), {code});
}

export class NativeIncoming {
  #route;
  #handle;
  #wake;
  #done = false;
  #terminal = false;
  #retentionRegistered = false;
  #retained = false;
  #released = false;

  /** `wake` schedules the host drain, which settles terminal closes. */
  constructor(native, descriptor, wake) {
    this.#route = new WeakRef(native);
    this.#handle = descriptor.handle;
    this.#wake = wake;
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
        incoming.#release();
      }
    });
    finalizers.register(this, {handle: this.#handle, route: this.#route}, this);
  }

  /** Retains serving capacity through completion of work that can outlive stream cancellation. */
  retainUntil(retired) {
    if (this.#done || this.#retentionRegistered) throw failure("NetworkIncomingRetentionInvalid");
    this.#retentionRegistered = true;
    this.#retained = true;
    const release = () => {
      this.#retained = false;
      this.#release();
    };
    Promise.resolve(retired).then(release, release);
  }

  #release() {
    if (!this.#done || this.#retained || this.#released) return;
    this.#released = true;
    try {
      this.#route.deref()?.incomingRelease(this.#handle);
    } catch {
      // Runtime teardown also releases native serving capacity.
    }
  }

  respond(data, context) {
    if (this.#done || this.#terminal) return Promise.reject(failure("NetworkIncomingClosed"));
    const native = this.#route.deref();
    if (!native) return Promise.reject(failure("NetworkClosed"));
    try {
      return native.incomingRespond(this.#handle, data, context);
    } catch (error) {
      return Promise.reject(error);
    }
  }

  ready() {
    if (this.#done || this.#terminal) return Promise.reject(failure("NetworkIncomingClosed"));
    const native = this.#route.deref();
    if (!native) return Promise.reject(failure("NetworkClosed"));
    try {
      return native.incomingReady(this.#handle);
    } catch (error) {
      return Promise.reject(error);
    }
  }

  #end(action, status, message) {
    if (this.#done || (this.#terminal && action !== 2)) return this.closed;
    try {
      this.#route.deref()?.incomingTerminal(this.#handle, action, status, message);
      this.#terminal = true;
      this.#wake();
      return this.closed;
    } catch (error) {
      if (error.code === "NetworkIncomingClosed") return this.closed;
      return Promise.reject(error);
    }
  }

  finish() {
    return this.#end(0);
  }
  fail(status, message) {
    return this.#end(1, status, message);
  }
  cancel() {
    return this.#end(2);
  }
}
