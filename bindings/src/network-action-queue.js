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
    case "reportPeer": {
      const origin = action.context?.origin;
      const endpoint = origin?.endpoint;
      const address = endpoint
        ? `${endpoint.family}:${Buffer.from(endpoint.address).toString("hex")}:${endpoint.port}`
        : "unknown";
      return `report:${action.action}:${action.peerId}:${action.context?.reason ?? "host"}:${origin ? `${origin.connection.index}:${origin.connection.generation}:${address}` : "unknown"}`;
    }
    default:
      return action.type;
  }
}

/** @param {Extract<Action, {type: "reportPeer"}>} action */
function copyReport(action) {
  const copy = {...action};
  if (!action.context) return copy;
  const context = {...action.context};
  copy.context = context;
  if (context.origin) {
    const {connection, endpoint} = context.origin;
    context.origin = {
      connection: {...connection},
      endpoint: endpoint ? {...endpoint, address: new Uint8Array(endpoint.address)} : null,
    };
  }
  return copy;
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
    this.#coalesced.set(key, action.type === "reportPeer" ? copyReport(action) : action);
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

  pending() {
    return this.#obligations.length > 0 || this.#coalesced.size > 0;
  }
}
