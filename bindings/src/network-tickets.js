import {Turns} from "./network-pump.js";

/** The families whose completions the owner settles, each with a record per native cell. */
const FAMILIES = ["publication", "command", "request", "incoming"];
/** The longest timer period, whose timer only holds what it is given and keeps the event loop alive. */
const HOLD_MS = 2 ** 31 - 1;
const noop = () => undefined;

/**
 * One family's records, a slot per native cell. A handle `{index, generation}` names a record: it is installed before
 * the admitting call yields and cleared by its cell's final completion before that settles it. A cell's generation
 * only grows and never wraps, so a completion for an older generation than its slot's is obsolete.
 */
class Records {
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
   * The live record `handle` names, cleared from its slot when `final`: undefined for an obsolete generation, and null
   * when no live record of its current generation matches.
   */
  take({index, generation}, final) {
    if (!(index < this.#records.length)) return null;
    if (generation < this.#generations[index]) return undefined;
    const record = this.#records[index];
    if (generation !== this.#generations[index] || record === null) return null;
    if (final) {
      this.#records[index] = null;
      this.live--;
    }
    return record;
  }
}

/**
 * Whether `completion` is its cell's last: a request's terminal outcome, an incoming stream's close, or a publication's
 * or command's only completion.
 */
function final(family, completion) {
  if (family === "request") return !("value" in completion);
  if (family === "incoming") return completion.closed === true;
  return true;
}

/**
 * Settles `record` with its cell's `completion`. A request's chunk answers its pending pull and its terminal outcome
 * ends the request; an incoming stream's completion settles its pending call and its close; any other family's single
 * completion settles the promise of the kind it expects. Returns false when the record cannot take the completion.
 */
function settle(family, record, completion) {
  if (family === "request") {
    if ("value" in completion) return record.chunk(completion.value);
    record.end(completion);
    return true;
  }
  if (family === "incoming") return record.complete(completion);
  if (record.kind !== completion.kind) return false;
  if ("error" in completion) record.reject(completion.error);
  else record.resolve(completion.value);
  return true;
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
  /**
   * From native's last notification until its close result arrives. Native then released its notifier, so this holds
   * the owner and keeps the event loop alive for the exchanges that deliver the rest, also after the wrapper's
   * finalizer handed them to the owner.
   */
  #hold = undefined;
  #closed = false;
  /** The runtime's one scheduling flag and retry timer, which a pump shares while it lives. */
  turns = new Turns(this);

  constructor(native, notify) {
    this.#native = native;
    this.#notify = notify;
  }

  /** Native's notification: a live wrapper takes it, and otherwise the owner drains. */
  notifier = () => {
    if (!this.#closed && this.#hold === undefined && ["closed", "failed"].includes(this.#native.getState()))
      this.#hold = setInterval(noop, HOLD_MS, this);
    if (!this.#notify()) this.abandon();
    return true;
  };

  /** Sizes each family's records from native's `capacities`. */
  size(capacities) {
    for (const family of FAMILIES) this.#tables.set(family, new Records(capacities[family]));
  }

  /**
   * Admits one operation of `family` and `kind`, whose promise its cell's completion settles. The record is installed
   * before this returns.
   */
  admit(family, kind, submit) {
    const record = {kind, reject: null, resolve: null};
    const promise = new Promise((resolve, reject) => {
      record.resolve = resolve;
      record.reject = reject;
    });
    this.#install(family, record, submit);
    return promise;
  }

  /** Admits one outgoing request, whose completions settle its iterator's `record`. Returns the request's handle. */
  request(record, submit) {
    return this.#install("request", record, submit);
  }

  /** Takes one serving start, whose completions settle its stream's `record`, before the start is exposed. */
  serve(record) {
    this.#install("incoming", record, () => record.handle);
  }

  /**
   * `submit` reserves the native cell and returns its handle, and `record` is installed before this returns. A
   * submission that throws installs nothing.
   */
  #install(family, record, submit) {
    const handle = submit();
    if (!this.#tables.get(family)?.install(handle, record))
      this.#breach(`admitted ${family} ${handle?.index}:${handle?.generation}`);
    return handle;
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
    const record = table === undefined ? null : table.take(handle, final(family, completion));
    if (record === undefined) return;
    if (record === null || !settle(family, record, completion))
      this.#breach(`completed ${family} ${handle.index}:${handle.generation}`);
  }

  #close() {
    this.#closed = true;
    clearInterval(this.#hold);
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
