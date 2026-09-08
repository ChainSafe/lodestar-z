const finalizers = new FinalizationRegistry(({route, handle}) => {
  try { route.deref()?.requestRetire(handle, true); } catch {}
});

function failure(code) {
  return Object.assign(new Error(code), {code});
}

export class NativeRequest {
  #route;
  #handle;
  #busy = false;
  #done = false;
  #retirement;

  constructor(native, handle) {
    this.#route = new WeakRef(native);
    this.#handle = handle;
    finalizers.register(this, {route: this.#route, handle}, this);
  }

  [Symbol.asyncIterator]() { return this; }

  next() {
    if (this.#done) return Promise.resolve({done: true, value: undefined});
    if (this.#busy) return Promise.reject(failure("NetworkRequestBusy"));
    const native = this.#route.deref();
    if (!native) {
      this.#complete();
      return Promise.reject(failure("NetworkClosed"));
    }
    this.#busy = true;
    let pending;
    try { pending = native.requestPull(this.#handle); }
    catch (error) { pending = Promise.reject(error); }
    return pending.then(
      (result) => {
        this.#busy = false;
        if (result.done) this.#complete();
        return result;
      },
      (error) => {
        this.#busy = false;
        this.#complete();
        throw error;
      }
    );
  }

  #complete() {
    this.#done = true;
    finalizers.unregister(this);
  }

  #retire(throwing, value) {
    if (this.#retirement) return this.#retirement;
    let pending;
    if (this.#done) pending = Promise.resolve();
    else {
      this.#complete();
      try { pending = Promise.resolve(this.#route.deref()?.requestRetire(this.#handle, false)); }
      catch (error) { pending = Promise.reject(error); }
    }
    this.#retirement = pending.then(() => {
      if (throwing) throw value;
      return {done: true, value: undefined};
    });
    return this.#retirement;
  }

  return() { return this.#retire(false); }
  throw(value) { return this.#retire(true, value); }
}
