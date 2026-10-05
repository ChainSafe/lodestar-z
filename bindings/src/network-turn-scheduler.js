// @ts-check
/**
 * @typedef {import("./network-runtime.js").NativeNetworkApplicationRuntime} NativeNetworkApplicationRuntime
 * @typedef {import("./network-runtime.js").NativeEscalation} NativeEscalation
 * @typedef {"now" | "later" | "idle"} Continuation
 * @typedef {{turn(): Continuation}} Pump
 * @typedef {Pick<NativeNetworkApplicationRuntime, "exchange" | "fail">} Route
 */

const RETRY_MS = 25;

export const SETTLE_CELLS = 32;
/** Settlement and acknowledgements only: every payload quota zero and the capacities unchanged. */
export const CONTROL = Object.freeze({
  bytes: 0,
  capacity: null,
  checks: 0,
  claimOrdinary: false,
  messages: 0,
  peers: 0,
  servingStarts: 0,
  settleCells: SETTLE_CELLS,
});
/**
 * Formats `cause` for native `fail`, which terminates the process.
 *
 * @param {Pick<Route, "fail">} runtime
 * @param {NativeEscalation} site
 * @param {unknown} cause
 * @returns {never}
 */
export function escalate(runtime, site, cause) {
  const reason = typeof cause === "string" ? cause : cause instanceof Error ? cause.message : "unknown";
  runtime.fail(site, reason.replace(/[^\x20-\x7e]/g, "?").slice(0, 64));
  throw Error("Native escalation returned");
}

/**
 * One runtime's scheduled turns, with its one scheduling flag and one retry timer. A turn is the bound pump's while it
 * lives; once the pump was collected, it is a control-only exchange through the completion owner's `route`, until
 * native reports closed. It holds the pump weakly and the route strongly, so a scheduled turn roots the completion
 * owner but never the pump or its host.
 */
export class TurnScheduler {
  #route;
  /** @type {WeakRef<Pump> | null} */
  #pump = null;
  #scheduled = false;
  #running = false;
  #stopped = false;
  /** @type {ReturnType<typeof setTimeout> | undefined} */
  #retry = undefined;

  /** @param {Route} route */
  constructor(route) {
    this.#route = route;
  }

  /**
   * Makes each later turn `pump`'s while it lives.
   * @param {Pump} pump
   */
  bind(pump) {
    this.#pump = new WeakRef(pump);
  }

  schedule() {
    if (this.#scheduled || this.#running || this.#stopped) return;
    this.#scheduled = true;
    setImmediate(TurnScheduler.#run, this);
  }

  /** Native reported closed, or a turn escalated. */
  stop() {
    this.#stopped = true;
    if (this.#retry) clearTimeout(this.#retry);
    this.#retry = undefined;
  }

  /** @param {TurnScheduler} scheduler */
  static #run(scheduler) {
    scheduler.#scheduled = false;
    if (scheduler.#stopped) return;
    scheduler.#running = true;
    // A turn that throws runs again, since native may hold more.
    /** @type {Continuation} */
    let next = "now";
    try {
      const pump = scheduler.#pump?.deref();
      next = pump ? pump.turn() : scheduler.#drain();
    } finally {
      scheduler.#running = false;
      scheduler.#continue(next);
    }
  }

  /** @param {Continuation} next */
  #continue(next) {
    switch (next) {
      case "now":
        this.schedule();
        break;
      case "later":
        this.#retryLater();
        break;
      case "idle":
        break;
      default: {
        /** @type {never} */
        const invalid = next;
        throw new Error(`Invalid turn continuation: ${invalid}`);
      }
    }
  }

  /**
   * A control-only exchange; the route settles what it delivers. Notifications bring the next.
   * @returns {Continuation}
   */
  #drain() {
    let result;
    try {
      result = this.#route.exchange([], CONTROL);
    } catch (error) {
      this.stop();
      escalate(this.#route, "generated_batch", error);
    }
    return result.more ? "now" : "idle";
  }

  #retryLater() {
    if (this.#stopped) return;
    this.#retry ??= setTimeout(TurnScheduler.#retryFired, RETRY_MS, this).unref();
  }

  /** @param {TurnScheduler} scheduler */
  static #retryFired(scheduler) {
    scheduler.#retry = undefined;
    scheduler.schedule();
  }
}
