import {Turns} from "./network-pump.js";

/** Families whose operation settles once, from its cell's one completion. */
const ONE_SHOT = ["publication", "command"];

/**
 * One family's one-shot operation records, a slot per native cell. A handle `{index, generation}` names a record: it
 * is installed before the admitting call yields and cleared before its promise settles. A cell's generation only grows
 * and never wraps, so a completion for an older generation than its slot's is obsolete.
 */
class Operations {
  #records;
  #generations;
  live = 0;

  constructor(capacity) {
    this.#records = new Array(capacity).fill(null);
    this.#generations = new Array(capacity).fill(0n);
  }

  /** Installs `record` for `handle`, or returns false when its slot is live or its generation did not grow. */
  install({index, generation}, record) {
    if (!(index < this.#records.length) || this.#records[index] !== null || generation <= this.#generations[index])
      return false;
    this.#records[index] = record;
    this.#generations[index] = generation;
    this.live++;
    return true;
  }

  /**
   * Settles the record `completion` names, or ignores it for an obsolete generation. Returns false when no live record
   * of its current generation and kind matches.
   */
  complete(completion) {
    const {index, generation} = completion.handle;
    if (!(index < this.#records.length)) return false;
    if (generation < this.#generations[index]) return true;
    const record = this.#records[index];
    if (generation !== this.#generations[index] || record === null || record.kind !== completion.kind) return false;
    this.#records[index] = null;
    this.live--;
    if ("error" in completion) record.reject(completion.error);
    else record.resolve(completion.value);
    return true;
  }
}

/**
 * Owns one runtime's operation records and its route to native, and outlives the wrapper: native's notifications hold
 * it, so every admitted operation settles also after the wrapper and its host were collected. It forwards each
 * notification through `notify`, which reports whether a live wrapper took it; once none does, it stops native and
 * drains control alone on the runtime's turns. It holds the wrapper, the pump and the host only weakly.
 */
export class CompletionOwner {
  #native;
  #notify;
  /** Each migrated family's records, sized from native's cells. */
  #tables = new Map();
  #abandoned = false;
  /** The runtime's one scheduling flag and retry timer, which a pump shares while it lives. */
  turns = new Turns(this);

  constructor(native, notify) {
    this.#native = native;
    this.#notify = notify;
  }

  /** Native's notification: a live wrapper takes it, and otherwise the owner drains. */
  notifier = () => {
    if (!this.#notify()) this.abandon();
    return true;
  };

  /** Sizes each one-shot family's records from native's `capacities`. */
  size(capacities) {
    for (const family of ONE_SHOT) this.#tables.set(family, new Operations(capacities[family]));
  }

  /**
   * Admits one operation: `submit` reserves its native cell and returns the handle, and the record is installed before
   * this returns. A submission that throws creates no record.
   */
  admit(family, kind, submit) {
    const record = {kind, reject: null, resolve: null};
    const promise = new Promise((resolve, reject) => {
      record.resolve = resolve;
      record.reject = reject;
    });
    const handle = submit();
    if (!this.#tables.get(family)?.install(handle, record))
      this.#breach(`admitted ${family} ${handle?.index}:${handle?.generation}`);
    return promise;
  }

  /** One exchange: its completions settle their records, and its close result ends the turns. */
  exchange(actions, demand) {
    const result = this.#native.exchange(actions, demand);
    for (const completion of result.completions) this.#complete(completion);
    if (result.closed !== null) this.#close();
    return result;
  }

  fail(site, reason) {
    this.#native.fail(site, reason);
  }

  /** Stops native at once for a wrapper collected without close, then drains what it settles. */
  abandon() {
    if (!this.#abandoned) {
      this.#abandoned = true;
      this.#native.abandon();
    }
    this.turns.schedule();
  }

  #complete(completion) {
    const {family, handle} = completion;
    if (!this.#tables.get(family)?.complete(completion))
      this.#breach(`completed ${family} ${handle.index}:${handle.generation}`);
  }

  #close() {
    let live = 0;
    for (const table of this.#tables.values()) live += table.live;
    if (live > 0) this.#breach(`closed with records unsettled: ${live}`);
    this.turns.stop();
  }

  #breach(reason) {
    this.turns.stop();
    this.#native.fail("completion_contract", reason.slice(0, 64));
    throw Error("Native escalation returned");
  }
}
