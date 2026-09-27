const finalizers = new FinalizationRegistry(({route, handle}) => {
  try {
    route.deref()?.requestRetire(handle, true);
  } catch {
    // Runtime teardown may have already retired this handle.
  }
});

function failure(code) {
  return Object.assign(new Error(code), {code});
}

/**
 * One outgoing request's iterator state, which the completion owner holds from admission until the request's terminal
 * completion, and the iterator for as long as it lives. It has two resolver slots: a pending pull's, whose presence is
 * the iterator's `busy` and which keeps the iterator alive while it waits, and a pending return or throw's, which the
 * terminal completion settles after the pull.
 */
export class RequestRecord {
  /**
   * The pending pull's resolvers and its iterator, or null.
   * @type {{iterator: unknown, resolve: (result: unknown) => void, reject: (error: unknown) => void} | null}
   */
  pull = null;
  /**
   * Settles the pending return or throw, or null.
   * @type {(() => void) | null}
   */
  retirement = null;
  /**
   * The terminal completion that arrived while no pull waited, which the next pull takes.
   * @type {{error?: unknown} | null}
   */
  outcome = null;
  /** The iterator took its terminal outcome or retired, so it only reports done. */
  done = false;

  /** A chunk completion answers the pending pull. Returns false when none waits. */
  chunk(value) {
    const pull = this.pull;
    if (pull === null) return false;
    this.pull = null;
    pull.resolve({done: false, value});
    return true;
  }

  /** The terminal completion: a pending pull takes its outcome, or the iterator keeps it, and then a retirement ends. */
  end(completion) {
    const {pull, retirement} = this;
    this.pull = null;
    this.retirement = null;
    finalizers.unregister(this);
    if (pull !== null) {
      this.done = true;
      if ("error" in completion) pull.reject(completion.error);
      else pull.resolve({done: true, value: undefined});
    } else if (!this.done) this.outcome = completion;
    retirement?.();
  }
}

export class NativeRequest {
  #route;
  #handle;
  #record;
  #retirement;

  /** `record` is the request's state in the completion owner, which the request's completions settle. */
  constructor(native, handle, record) {
    this.#route = new WeakRef(native);
    this.#handle = handle;
    this.#record = record;
    finalizers.register(this, {handle, route: this.#route}, record);
  }

  [Symbol.asyncIterator]() {
    return this;
  }

  next() {
    const record = this.#record;
    if (record.done) return Promise.resolve({done: true, value: undefined});
    if (record.pull !== null) return Promise.reject(failure("NetworkRequestBusy"));
    const outcome = record.outcome;
    if (outcome !== null) {
      this.#finish();
      return "error" in outcome ? Promise.reject(outcome.error) : Promise.resolve({done: true, value: undefined});
    }
    const native = this.#route.deref();
    if (native === undefined) {
      this.#finish();
      return Promise.reject(failure("NetworkClosed"));
    }
    try {
      native.requestPull(this.#handle);
    } catch (error) {
      this.#finish();
      return Promise.reject(error);
    }
    return new Promise((resolve, reject) => {
      record.pull = {iterator: this, reject, resolve};
    });
  }

  #finish() {
    const record = this.#record;
    record.done = true;
    record.outcome = null;
    finalizers.unregister(record);
  }

  /** Retires the request once: every return or throw shares the first one's promise, which settles as it did. */
  #retire(throwing, value) {
    if (this.#retirement !== undefined) return this.#retirement;
    let resolve;
    let reject;
    const promise = new Promise((resolved, rejected) => {
      resolve = resolved;
      reject = rejected;
    });
    this.#retirement = promise;
    const settle = () => (throwing ? reject(value) : resolve({done: true, value: undefined}));
    const record = this.#record;
    // Native still streams a request whose terminal outcome neither arrived nor was taken.
    const streaming = !record.done && record.outcome === null;
    this.#finish();
    const native = streaming ? this.#route.deref() : undefined;
    if (native === undefined) {
      settle();
      return promise;
    }
    try {
      native.requestRetire(this.#handle, false);
      record.retirement = settle;
    } catch (error) {
      reject(error);
    }
    return promise;
  }

  return() {
    return this.#retire(false);
  }
  throw(value) {
    return this.#retire(true, value);
  }
}
