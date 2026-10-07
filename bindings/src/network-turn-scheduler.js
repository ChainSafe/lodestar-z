// @ts-check
/**
 * @typedef {import("./network-runtime.js").NativeNetworkApplicationRuntime} NativeNetworkApplicationRuntime
 * @typedef {import("./network-runtime.js").NativeEscalation} NativeEscalation
 * @typedef {"now" | "idle"} Continuation
 * @typedef {{turn(): Continuation}} Pump
 */

/** Settlement and acknowledgements only. */
export const CONTROL = Object.freeze({mode: /** @type {const} */ ("control")});
/**
 * Formats `cause` for native `fail`, which terminates the process.
 *
 * @param {Pick<NativeNetworkApplicationRuntime, "fail">} runtime
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
 * Schedules one pump's bounded turns through shutdown. Referenced immediates keep completion delivery alive after
 * native releases its notifier.
 */
export class TurnScheduler {
  #pump;
  #scheduled = false;
  #stopped = false;

  /** @param {Pump} pump */
  constructor(pump) {
    this.#pump = pump;
  }

  schedule() {
    if (this.#scheduled || this.#stopped) return;
    this.#scheduled = true;
    setImmediate(TurnScheduler.#run, this);
  }

  /** Native reported closed, or a turn escalated. */
  stop() {
    this.#stopped = true;
  }

  /** @param {TurnScheduler} scheduler */
  static #run(scheduler) {
    scheduler.#scheduled = false;
    if (scheduler.#stopped) return;
    // A turn that throws runs again, since native may hold more.
    /** @type {Continuation} */
    let next = "now";
    try {
      next = scheduler.#pump.turn();
    } finally {
      scheduler.#continue(next);
    }
  }

  /** @param {Continuation} next */
  #continue(next) {
    switch (next) {
      case "now":
        this.schedule();
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
}
