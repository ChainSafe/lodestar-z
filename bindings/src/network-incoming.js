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

/** Settles a pending call with its outcome: resolved, unless it names an error. */
function settle(pending, outcome) {
  if ("error" in outcome) pending.reject(outcome.error);
  else pending.resolve(undefined);
}

/**
 * One incoming stream's state, which the completion owner holds from the serving start until the stream's close
 * completion, and its facade for as long as that lives. Its slots: the one `closed` promise, and at most one pending
 * `ready` or `respond`. It also holds the stream's retention: once the stream closed and no host work retains it, the
 * serving slot returns to native.
 */
export class IncomingRecord {
  #resolveClosed = () => undefined;
  /**
   * The pending `ready` or `respond`: its kind and resolvers, or null.
   * @type {{kind: "ready" | "respond", resolve: (value: undefined) => void, reject: (error: unknown) => void} | null}
   */
  pending = null;
  /** The stream closed. */
  done = false;
  /** Host work that can outlive the stream holds its serving slot. */
  retained = false;
  #released = false;

  constructor(native, handle) {
    this.route = new WeakRef(native);
    this.handle = handle;
    this.closed = new Promise((resolve) => {
      this.#resolveClosed = resolve;
    });
  }

  /**
   * The incoming completion: the pending response's acknowledgement, then the stream's close, then the pending
   * permission's outcome. Returns false when it settles a call that is not pending.
   */
  complete(completion) {
    const kind = "response" in completion ? "respond" : "ready" in completion ? "ready" : null;
    const pending = this.pending;
    if (kind !== null && pending?.kind !== kind) return false;
    if (kind !== null) this.pending = null;
    if (kind === "respond") settle(pending, completion.response);
    if (completion.closed === true) {
      this.done = true;
      finalizers.unregister(this);
      this.release();
      this.#resolveClosed(undefined);
    }
    if (kind === "ready") settle(pending, completion.ready);
    return true;
  }

  /** Returns the serving slot once, when the stream closed and no host work retains it. */
  release() {
    if (!this.done || this.retained || this.#released) return;
    this.#released = true;
    try {
      this.route.deref()?.incomingRelease(this.handle);
    } catch {
      // Runtime teardown also releases native serving capacity.
    }
  }

  /** Cancels a stream no facade serves, and returns its slot. */
  abandon() {
    this.#released = true;
    try {
      this.route.deref()?.incomingTerminal(this.handle, 2, undefined, undefined);
      this.route.deref()?.incomingRelease(this.handle);
    } catch {
      // Runtime teardown also releases native serving capacity.
    }
  }
}

export class NativeIncoming {
  #record;
  #terminal = false;
  #retentionRegistered = false;

  /** `record` is the stream's state in the completion owner, which the stream's completions settle. */
  constructor(descriptor, record) {
    this.#record = record;
    this.peerId = descriptor.peerId;
    this.connection = descriptor.connection;
    this.protocol = descriptor.protocol;
    this.data = descriptor.data;
    this.closed = record.closed;
    finalizers.register(this, {handle: record.handle, route: record.route}, record);
  }

  /** Retains serving capacity through completion of work that can outlive stream cancellation. */
  retainUntil(retired) {
    const record = this.#record;
    if (record.done || this.#retentionRegistered) throw failure("NetworkIncomingRetentionInvalid");
    this.#retentionRegistered = true;
    record.retained = true;
    const release = () => {
      record.retained = false;
      record.release();
    };
    Promise.resolve(retired).then(release, release);
  }

  respond(data, context) {
    return this.#await("respond", (native, handle) => native.incomingRespond(handle, data, context));
  }

  ready() {
    return this.#await("ready", (native, handle) => native.incomingReady(handle));
  }

  /** Arms a `ready` or `respond`, whose completion settles the promise this returns. */
  #await(kind, arm) {
    const record = this.#record;
    if (record.done || this.#terminal) return Promise.reject(failure("NetworkIncomingClosed"));
    const native = record.route.deref();
    if (!native) return Promise.reject(failure("NetworkClosed"));
    try {
      arm(native, record.handle);
    } catch (error) {
      return Promise.reject(error);
    }
    return new Promise((resolve, reject) => {
      record.pending = {kind, reject, resolve};
    });
  }

  #end(action, status, message) {
    const record = this.#record;
    if (record.done || (this.#terminal && action !== 2)) return this.closed;
    try {
      record.route.deref()?.incomingTerminal(record.handle, action, status, message);
      this.#terminal = true;
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
