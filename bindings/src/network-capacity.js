// @ts-check

const WAITERS_MAX = 32;
const TIMEOUT_MAX_MS = 60000;

/** @param {string} code */
function failure(code) {
  return Object.assign(new Error(code), {code});
}

/**
 * @typedef {{requestCapacityWatch(token: string): boolean}} Runtime
 * @typedef {{token: string, finish(error?: unknown): void}} Waiter
 */
export class RequestCapacityWaiters {
  /** @type {Runtime} */
  #runtime;
  /** @type {Set<Waiter>} */
  #waiters = new Set();
  #closed = false;

  /** @param {Runtime} runtime */
  constructor(runtime) {
    this.#runtime = runtime;
  }

  /**
   * @param {string} token
   * @param {{signal: AbortSignal, timeoutMs: number}} options
   * @returns {Promise<void>}
   */
  async wait(token, {signal, timeoutMs}) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > TIMEOUT_MAX_MS)
      throw failure("InvalidRequestCapacityTimeout");
    if (typeof signal?.addEventListener !== "function" || typeof signal?.removeEventListener !== "function")
      throw failure("InvalidRequestCapacitySignal");
    if (this.#closed) throw failure("NetworkClosed");
    if (signal.aborted) throw failure("NetworkRequestCapacityCancelled");
    if (this.#waiters.size === WAITERS_MAX) throw failure("NetworkRequestCapacityWaitersFull");
    return new Promise((resolve, reject) => {
      const abort = () => waiter.finish(failure("NetworkRequestCapacityCancelled"));
      const timer = setTimeout(() => waiter.finish(failure("NetworkRequestCapacityTimeout")), timeoutMs);
      /** @type {Waiter} */
      const waiter = {
        finish: (error) => {
          if (!this.#waiters.delete(waiter)) return;
          clearTimeout(timer);
          signal.removeEventListener("abort", abort);
          if (error !== undefined) reject(error);
          else resolve();
        },
        token,
      };
      this.#waiters.add(waiter);
      signal.addEventListener("abort", abort, {once: true});
      if (signal.aborted) abort();
      else this.#check(waiter);
    });
  }

  changed() {
    for (const waiter of this.#waiters) this.#check(waiter);
  }

  /** @param {Waiter} waiter */
  #check(waiter) {
    try {
      if (this.#runtime.requestCapacityWatch(waiter.token)) waiter.finish();
    } catch (error) {
      waiter.finish(error);
    }
  }

  close() {
    this.#closed = true;
    for (const waiter of this.#waiters) waiter.finish(failure("NetworkClosed"));
  }
}
