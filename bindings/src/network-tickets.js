import {Turns} from "./network-pump.js";

/**
 * One family's operation records, a slot per native cell. A handle `{index, generation}` names a record: it is
 * installed before the admitting call yields and taken, cleared, before its promise settles. A cell's generation only
 * grows and never wraps, so a completion for an older generation than its slot's is obsolete.
 */
class Table {
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

  obsolete({index, generation}) {
    return index < this.#records.length && generation < this.#generations[index];
  }

  /** The live record of `handle`'s current generation, cleared, or null when there is none. */
  take({index, generation}) {
    if (!(index < this.#records.length) || generation !== this.#generations[index]) return null;
    const record = this.#records[index];
    if (record === null) return null;
    this.#records[index] = null;
    this.live--;
    return record;
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
  /** Each family's records, sized from native's cells. */
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

  /** Sizes each family's records from native's `capacities`. */
  size(capacities) {
    for (const [family, capacity] of Object.entries(capacities)) this.#tables.set(family, new Table(capacity));
  }

  /**
   * Admits one operation: `submit` reserves its native cell and returns the handle, and the record is installed before
   * this returns. A submission that throws creates no record.
   */
  admit(family, kind, submit) {
    let resolve;
    let reject;
    const promise = new Promise((res, rej) => {
      resolve = res;
      reject = rej;
    });
    const handle = submit();
    if (!this.#tables.get(family)?.install(handle, {kind, reject, resolve}))
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
    const table = this.#tables.get(family);
    if (table?.obsolete(handle)) return;
    const record = table?.take(handle) ?? null;
    if (record === null || record.kind !== completion.kind)
      this.#breach(`completed ${family} ${handle.index}:${handle.generation}`);
    if ("error" in completion) record.reject(completion.error);
    else record.resolve(completion.value);
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
