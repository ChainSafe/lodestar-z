// @ts-check
/**
 * @typedef {import("./network-runtime.js").NativeAction} Action
 * @typedef {Extract<Action, {type: "block" | "reportPeer" | "dropQueued" | "recheck"}>} CoalescedAction
 */

/** Actions one exchange applies; native refuses a longer batch. */
export const ACTION_MAX = 256;
/** Imported roots coalesced between exchanges; more become one recheck of every waiting message. */
const BLOCK_MAX = 256;
/** Coalesced peer penalty entries, each saturating as native does; more are dropped and counted. */
const REPORT_ENTRY_MAX = 512;
const REPORT_COUNT_MAX = 100;

/** @param {CoalescedAction} action */
function coalescingKey(action) {
  switch (action.type) {
    case "block":
      return `block:${Buffer.from(action.root).toString("hex")}`;
    case "reportPeer":
      return `report:${action.action}:${action.peerId}`;
    default:
      return action.type;
  }
}

/** Obligations retain their order and precede coalesced requests in every exchange. */
export class ActionQueue {
  /** @type {Action[]} */
  #obligations = [];
  /**
   * One entry per imported root, per penalized peer and action, and for a recheck or a drop, in arrival order.
   * @type {Map<string, CoalescedAction>}
   */
  #coalesced = new Map();
  #blocks = 0;
  #reports = 0;
  reportsDropped = 0;

  /** @param {Action} action */
  enqueue(action) {
    if (action.type === "verdict" || action.type === "classify") this.#obligations.push(action);
    else this.#add(action);
  }

  /**
   * Queues a coalesced request, merging a penalty into its entry, within the queue's bounds.
   * @param {CoalescedAction} action
   */
  #add(action) {
    const key = coalescingKey(action);
    const queued = this.#coalesced.get(key);
    if (queued) {
      if (queued.type === "reportPeer" && action.type === "reportPeer")
        queued.count = Math.min(REPORT_COUNT_MAX, queued.count + action.count);
      return;
    }
    if (action.type === "block") {
      if (this.#coalesced.has("recheck")) return;
      if (this.#blocks === BLOCK_MAX) {
        for (const [queuedKey, {type}] of this.#coalesced) if (type === "block") this.#coalesced.delete(queuedKey);
        this.#blocks = 0;
        this.#coalesced.set("recheck", {type: "recheck"});
        return;
      }
      this.#blocks++;
    } else if (action.type === "reportPeer") {
      if (this.#reports === REPORT_ENTRY_MAX) {
        this.reportsDropped++;
        return;
      }
      this.#reports++;
    }
    // A penalty is copied, so an entry in flight never changes.
    this.#coalesced.set(key, action.type === "reportPeer" ? {...action} : action);
  }

  /** Moves up to `ACTION_MAX` queued actions into one batch; what arrives meanwhile queues for the next one. */
  take() {
    const batch = this.#obligations.splice(0, ACTION_MAX);
    for (const [key, action] of this.#coalesced) {
      if (batch.length === ACTION_MAX) break;
      this.#coalesced.delete(key);
      if (action.type === "block") this.#blocks--;
      else if (action.type === "reportPeer") this.#reports--;
      batch.push(action);
    }
    return batch;
  }

  /**
   * Returns a batch native never applied to the queue.
   * @param {Action[]} batch
   */
  restore(batch) {
    this.#obligations.unshift(...batch.filter(({type}) => type === "verdict" || type === "classify"));
    for (const action of batch) if (action.type !== "verdict" && action.type !== "classify") this.#add(action);
  }

  pending() {
    return this.#obligations.length > 0 || this.#coalesced.size > 0;
  }
}
