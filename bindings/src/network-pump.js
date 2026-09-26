/** Actions one exchange applies; native refuses a longer batch. */
export const ACTION_MAX = 256;
/** Imported roots coalesced between exchanges; more become one recheck of every waiting message. */
const BLOCK_MAX = 256;
/** Coalesced peer penalty entries, each saturating as native does; more are dropped and counted. */
const REPORT_ENTRY_MAX = 512;
const REPORT_COUNT_MAX = 100;
const RETRY_MS = 25;
/** Consecutive failed turns, each counted once for a failed capacity read or exchange, before escalating. */
const FAILURES_MAX = 3;
/** One turn's time budget; the rest yields to the next turn. */
export const BUDGET_MS = 8;
/** Completions settled per native table in one turn. */
const SETTLE_CELLS = 32;
/** Serving capacity native accepts. */
const SERVING_MAX = 32;
/** Per-turn quotas of each payload source. */
export const QUOTAS = Object.freeze({bytes: 8 * 1024 * 1024, checks: 64, messages: 64, peers: 32, servingStarts: 8});
/** Settlement and acknowledgements only: every payload quota zero and the capacities unchanged. */
const CONTROL = Object.freeze({
  bytes: 0,
  capacity: null,
  checks: 0,
  claimOrdinary: false,
  messages: 0,
  peers: 0,
  servingStarts: 0,
  settleCells: SETTLE_CELLS,
});
export const BURST_NAME = "lodestar_native_drain_burst_seconds";
export const BURST_BUCKETS = Object.freeze([0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2]);
const VERDICTS = new Set(["accept", "reject", "ignore"]);
const noop = () => undefined;

function closedError() {
  return Object.assign(new Error("NetworkClosed"), {code: "NetworkClosed"});
}

function contractError(callback) {
  return Object.assign(new Error(`NativeHostContract: ${callback}`), {callback, code: "NativeHostContract"});
}

function keyOf(handle) {
  return `${handle.index}:${handle.generation}`;
}

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

/** The public view of a serving start: the native handle and retention stay with the binding. */
class IncomingRequest {
  #incoming;

  constructor(incoming) {
    this.#incoming = incoming;
    this.peerId = incoming.peerId;
    this.connection = incoming.connection;
    this.protocol = incoming.protocol;
    this.data = incoming.data;
    this.closed = incoming.closed;
  }

  ready() {
    return this.#incoming.ready();
  }
  respond(data, context) {
    return this.#incoming.respond(data, context);
  }
  finish() {
    return this.#incoming.finish();
  }
  fail(status, message) {
    return this.#incoming.fail(status, message);
  }
  cancel() {
    return this.#incoming.cancel();
  }
}

/**
 * Drains one runtime for one host: native exchanges in bounded macrotasks, each sending queued obligations first,
 * then coalesced requests, and handing peers, serving starts, dependency checks and gossip jobs to the host in that
 * order. It turns again at once while native reports more, actions or held deliveries remain, or the time budget left
 * ordinary work, and after its one retry timer while work waits for external capacity or a disabled service, or after
 * a failed turn. A null host capacity, or a closing facade, leaves settlement and acknowledgements only, until native
 * reports closed. A broken bridge contract escalates through native `fail`, which terminates the process.
 *
 * Scheduled callbacks and the closed observation hold the pump weakly, so a dropped facade and host can be collected.
 */
export class NativePump {
  #runtime = null;
  #host;
  /** Terminal bookkeeping the facade shares; it holds no host reference. */
  #terminal;
  #weak = new WeakRef(this);
  #scheduled = false;
  #running = false;
  #closing = false;
  #stopped = false;
  #retry = undefined;
  /** Consecutive turns whose capacity read threw or whose exchange could not run. */
  #failures = 0;
  #obligations = [];
  /** One entry per imported root, per penalized peer and action, and for a recheck or a drop, in arrival order. */
  #coalesced = new Map();
  #blocks = 0;
  #reports = 0;
  /** Delivered ordinary jobs a spent time budget left for the next turn, at most one batch. */
  #heldJobs = [];
  /** Delivered serving starts a spent time budget left for the next turn, at most one turn's quota. */
  #heldStarts = [];
  /**
   * Each delivered message awaiting its owner disposition, by native handle. The closed observation holds it without
   * the pump, so reports a host retains settle at close although the pump and host were collected.
   */
  #reported = new Map();
  #burst = {buckets: new Array(BURST_BUCKETS.length).fill(0), count: 0, sum: 0};
  /** Peer penalties dropped because the coalescing table was full. */
  reportsDropped = 0;

  constructor(host, terminal) {
    this.#host = host;
    this.#terminal = terminal;
  }

  /** Starts draining `runtime`, whose notifications call `request`. */
  attach(runtime) {
    this.#runtime = runtime;
    NativePump.#observe(this.#weak, this.#reported, runtime.closed);
  }

  static #observe(weak, reported, closed) {
    const stop = () => {
      // Shutdown prevents the owner from disposing of whatever it has not acknowledged.
      const jobs = new Set(reported.values());
      reported.clear();
      for (const job of jobs) job.reject(closedError());
      const pump = weak.deref();
      if (pump) pump.#stop();
    };
    closed.then(stop, stop);
  }

  /** A native notification, or capacity the host released. */
  request = () => this.#schedule();

  block(root) {
    this.#coalesce({root, type: "block"});
  }
  dropQueued() {
    this.#coalesce({type: "dropQueued"});
  }
  reportPeer(peerId, action) {
    this.#coalesce({action, count: 1, peerId, type: "reportPeer"});
  }

  /**
   * Leaves settlement only: held serving starts are cancelled and held jobs dropped, as native close retires their
   * messages. Turns continue until native reports closed.
   */
  close() {
    if (this.#closing) return;
    this.#closing = true;
    const starts = this.#heldStarts;
    this.#heldStarts = [];
    for (const incoming of starts) void incoming.cancel().catch(noop);
    this.#heldJobs = [];
  }

  /** A fatal failure after a delivery: the first is the close result's error, and the network closes. */
  #fail(error) {
    if (this.#stopped) return;
    this.#terminal.failure ??=
      error instanceof Error ? error : Object.assign(new Error("NativeHostFailure"), {cause: error});
    this.close();
    try {
      this.#runtime.close();
    } catch {
      // A runtime that cannot close is already closing.
    }
  }

  /** An operational failure the pump recovered from, for the host to log. */
  #error(error) {
    try {
      this.#host.error?.(error);
    } catch {
      // Reporting a recovered failure must not stop the pump.
    }
  }

  #coalesce(action) {
    if (this.#stopped) return;
    this.#add(action);
    this.#schedule();
  }

  /** Queues a coalesced request, merging a penalty into its entry, within the ledger's bounds. */
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
  #take() {
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

  /** Returns a batch native never applied to the ledger. */
  #requeue(batch) {
    this.#obligations.unshift(...batch.filter(({type}) => type === "verdict" || type === "classify"));
    for (const action of batch) if (action.type !== "verdict" && action.type !== "classify") this.#add(action);
  }

  #pending() {
    return this.#obligations.length > 0 || this.#coalesced.size > 0;
  }

  #schedule() {
    if (this.#scheduled || this.#running || this.#stopped || this.#runtime === null) return;
    this.#scheduled = true;
    setImmediate(NativePump.#runWeak, this.#weak);
  }

  static #runWeak(weak) {
    const pump = weak.deref();
    if (pump) pump.#run();
  }

  #retryLater(failed) {
    if (this.#stopped) return;
    this.#retry ??= setTimeout(NativePump.#retryFired, RETRY_MS, this.#weak).unref();
    // A failed exchange retries until it settles or escalates, also when nothing else keeps the process alive.
    if (failed) this.#retry.ref();
  }

  static #retryFired(weak) {
    const pump = weak.deref();
    if (!pump) return;
    pump.#retry = undefined;
    pump.#schedule();
  }

  #stop() {
    this.#stopped = true;
    if (this.#retry) clearTimeout(this.#retry);
    this.#retry = undefined;
    this.close();
  }

  #escalate(trigger, cause) {
    this.#stop();
    const reason = typeof cause === "string" ? cause : cause instanceof Error ? cause.message : "unknown";
    this.#runtime.fail(trigger, reason.replace(/[^\x20-\x7e]/g, "?").slice(0, 64));
    throw Error("Native escalation returned");
  }

  #run() {
    this.#scheduled = false;
    if (this.#stopped) return;
    const started = performance.now();
    this.#running = true;
    // A turn that throws runs again, since native may hold more.
    let next = "now";
    try {
      next = this.#turn(started + BUDGET_MS);
    } finally {
      this.#running = false;
      // The burst end is queued first, so it covers only this turn.
      setImmediate(NativePump.#burstEnd, this.#weak, started);
      // Actions queued while the turn ran need one too, unless its exchange failed.
      if (next === "now" || (next !== "retry" && this.#pending())) this.#schedule();
      else if (next !== "idle") this.#retryLater(next === "retry");
    }
  }

  /** The host's demand for this turn, or null for settlement only. Throws what the host's capacity read threw. */
  #demand(deadline) {
    if (this.#closing) return null;
    const capacity = this.#host.capacity();
    if (capacity === null) return null;
    const serving = capacity?.serving;
    if (typeof serving !== "number" || !Number.isFinite(serving) || typeof capacity.ordinary !== "boolean")
      throw contractError("capacity");
    return {
      bytes: QUOTAS.bytes,
      capacity: {
        ordinary: capacity.ordinary,
        // Held starts are delivered but not started, so they count once against the host's free capacity.
        serving: Math.min(SERVING_MAX, Math.max(0, Math.floor(serving) - this.#heldStarts.length)),
      },
      checks: QUOTAS.checks,
      // Ordinary work is claimed only while no delivered job waits and the budget lasts.
      claimOrdinary: this.#heldJobs.length === 0 && performance.now() < deadline,
      messages: QUOTAS.messages,
      peers: QUOTAS.peers,
      servingStarts: Math.max(0, QUOTAS.servingStarts - this.#heldStarts.length),
      settleCells: SETTLE_CELLS,
    };
  }

  #turn(deadline) {
    let demand = null;
    let failed = false;
    try {
      demand = this.#demand(deadline);
    } catch (error) {
      // The turn still settles control; the capacity read retries on the timer.
      if (++this.#failures >= FAILURES_MAX) this.#escalate(3, error);
      failed = true;
      this.#error(error);
    }
    const batch = this.#take();
    let result;
    try {
      result = this.#runtime.exchange(batch, demand ?? CONTROL);
    } catch (error) {
      // Native refuses only an invalid batch or a nested exchange, so a refusal of this generated batch is a
      // broken contract. Anything else left native untouched: the batch requeues and the turn retries.
      const code = error?.code;
      if (typeof code === "string") this.#escalate(1, code);
      this.#requeue(batch);
      // A turn whose capacity read failed has counted already.
      if (!failed && ++this.#failures >= FAILURES_MAX) this.#escalate(3, error);
      this.#error(error);
      return "retry";
    }
    // Any exchange that ran without a failed capacity read ends the run, a settling one after close included.
    if (!failed) this.#failures = 0;
    this.#acknowledge(result.acknowledged);
    let held = false;
    let failure = result.failure;
    try {
      if (demand !== null) held = this.#deliver(result, deadline);
    } catch (error) {
      failure ??= error;
    }
    // Ordinary work the time budget left unclaimed waits for the next turn, as held jobs do.
    const budgetEnded = demand !== null && demand.messages > 0 && !demand.claimOrdinary;
    let next = "idle";
    if (result.more || held || (budgetEnded && result.disabledWaiting)) next = "now";
    else if (failed || result.parked.serving || result.parked.ordinary || result.disabledWaiting) next = "later";
    if (failure !== null) this.#fail(failure);
    return next;
  }

  /** Resolves each job whose every message the owner has now disposed of. */
  #acknowledge(acknowledged) {
    for (const handle of acknowledged ?? []) {
      const key = keyOf(handle);
      const job = this.#reported.get(key);
      if (!job) continue;
      this.#reported.delete(key);
      if (--job.remaining === 0) job.resolve();
    }
  }

  /**
   * Hands one exchange's delivery to the host: peers, then serving starts, then dependency checks, then gossip jobs.
   * If the host's peer handler throws, the pump keeps what it never handed over: every job gets an ignore verdict,
   * every serving start is cancelled once and every check is classified unavailable. Returns whether delivered work
   * waits for the next turn.
   */
  #deliver(result, deadline) {
    const jobs = this.#jobs(result.gossip);
    const starts = result.serving.map((incoming) => ({adopted: false, incoming}));
    const checks = result.checks;
    let checked = checks.length === 0;
    try {
      if (result.peers.length > 0) this.#host.peers(result.peers);
      const heldStarts = this.#start(starts, deadline);
      this.#check(checks);
      checked = true;
      const heldJobs = this.#dispatch(jobs, deadline);
      return heldStarts || heldJobs;
    } finally {
      for (const job of jobs) if (!job.adopted) this.#verdicts(job, null);
      for (const start of starts) if (!start.adopted) void start.incoming.cancel().catch(noop);
      if (!checked) for (const {handle} of checks) this.#obligations.push({available: false, handle, type: "classify"});
    }
  }

  /** Jobs with host records that physically omit native handles, each awaiting every message's disposition. */
  #jobs(gossip) {
    if (!gossip) return [];
    return gossip.jobs.map(({kind, grouped, urgent, start, length}) => {
      const natives = gossip.messages.slice(start, start + length);
      let resolve;
      let reject;
      const reported = new Promise((res, rej) => {
        resolve = res;
        reject = rej;
      });
      // A host that does not await a job's disposition sees no unhandled rejection at shutdown.
      reported.catch(noop);
      const settle = {reject, remaining: natives.length, resolve};
      for (const {handle} of natives) this.#reported.set(keyOf(handle), settle);
      const messages = natives.map((message) => ({
        attestationData: message.attestationData,
        connection: message.connection,
        data: message.data,
        id: message.id,
        peerId: message.peerId,
        receivedAtUnixMs: message.receivedAtUnixMs,
        slot: message.slot,
        topic: message.topic,
      }));
      return {
        adopted: false,
        handles: natives.map(({handle}) => handle),
        job: {grouped, kind, messages, reported},
        urgent,
      };
    });
  }

  /**
   * Starts the held and delivered serving starts in that order, unless the budget is spent: they then wait for the
   * next turn. Returns whether starts wait.
   */
  #start(starts, deadline) {
    const pending = this.#heldStarts;
    this.#heldStarts = [];
    for (const start of starts) {
      start.adopted = true;
      pending.push(start.incoming);
    }
    if (pending.length > 0 && performance.now() >= deadline) {
      this.#heldStarts = pending;
      return true;
    }
    for (const incoming of pending) this.#serve(incoming);
    return false;
  }

  /**
   * Hands one serving start to the host. Its serving capacity stays charged until the host's promise settles, which
   * the binding registers before host code runs. A throw or rejection fails the stream.
   */
  #serve(incoming) {
    let release;
    const retired = new Promise((resolve) => {
      release = resolve;
    });
    try {
      incoming.retainUntil(retired);
    } catch {
      // The stream ended while the start was held: there is nothing left to serve.
      release();
      return;
    }
    let served;
    try {
      served = Promise.resolve(this.#host.serve(new IncomingRequest(incoming)));
    } catch (error) {
      served = Promise.reject(error);
    }
    NativePump.#served(this.#weak, served, incoming, release);
  }

  static #served(weak, served, incoming, release) {
    served.then(
      () => {
        release();
        const pump = weak.deref();
        if (pump) pump.#schedule();
      },
      (error) => {
        void incoming.fail(2, new TextEncoder().encode("Local serving failure")).catch(noop);
        release();
        const pump = weak.deref();
        if (!pump) return;
        pump.#error(error);
        pump.#schedule();
      }
    );
  }

  /** Classifies every check with the host's answers, or unavailable when it cannot answer them all. */
  #check(checks) {
    if (checks.length === 0) return;
    let available = null;
    try {
      const answers = this.#host.checkDependencies(
        checks.map(({root, slot, peerId, topic}) => ({peerId, root, slot, topic}))
      );
      // Every index is checked, since array methods skip the holes of a sparse array.
      const answered = Array.isArray(answers) && answers.length === checks.length;
      if (!answered || !checks.every((_, i) => typeof answers[i] === "boolean"))
        throw contractError("checkDependencies");
      available = answers;
    } catch (error) {
      this.#error(error);
    }
    for (const [i, {handle}] of checks.entries())
      this.#obligations.push({available: available !== null && available[i], handle, type: "classify"});
  }

  /**
   * Starts every urgent job now, whatever the budget, and queues ordinary jobs, which start until `deadline`: at least
   * one per turn unless the budget was spent before this delivery and no job was held. Returns whether jobs wait.
   */
  #dispatch(jobs, deadline) {
    // Ordinary work delivered at the turn's start is new work, which a spent budget defers like the claim it replaced.
    const progress = this.#heldJobs.length > 0 || performance.now() < deadline;
    // Jobs arrive in priority order, so urgent jobs start first and none waits for the budget.
    for (const job of jobs) {
      job.adopted = true;
      if (job.urgent) this.#validate(job);
      else this.#heldJobs.push(job);
    }
    let started = 0;
    for (const job of this.#heldJobs) {
      if ((started > 0 || !progress) && performance.now() >= deadline) break;
      started++;
      this.#validate(job);
    }
    this.#heldJobs = this.#heldJobs.slice(started);
    return this.#heldJobs.length > 0;
  }

  /** Hands one job to the host. A throw, a rejection or the wrong verdicts ignore every message. */
  #validate(record) {
    const {job} = record;
    record.job = null;
    let verdicts;
    try {
      verdicts = Promise.resolve(this.#host.validate(job));
    } catch (error) {
      verdicts = Promise.reject(error);
    }
    NativePump.#validated(this.#weak, verdicts, record);
  }

  static #validated(weak, verdicts, record) {
    verdicts.then(
      (values) => {
        const pump = weak.deref();
        if (pump) pump.#verdicts(record, values);
      },
      (error) => {
        const pump = weak.deref();
        if (!pump) return;
        pump.#error(error);
        pump.#verdicts(record, null);
      }
    );
  }

  /** Queues one verdict per message, in order; anything but one valid verdict per message ignores them all. */
  #verdicts(record, values) {
    if (this.#stopped) return;
    const count = record.handles.length;
    const valid =
      Array.isArray(values) && values.length === count && record.handles.every((_, i) => VERDICTS.has(values[i]));
    if (values !== null && !valid) this.#error(contractError("validate"));
    for (let i = 0; i < count; i++)
      this.#obligations.push({handle: record.handles[i], type: "verdict", verdict: valid ? values[i] : "ignore"});
    this.#schedule();
  }

  static #burstEnd(weak, started) {
    const pump = weak.deref();
    if (!pump) return;
    const value = (performance.now() - started) / 1000;
    const burst = pump.#burst;
    burst.count++;
    burst.sum += value;
    for (let i = 0; i < BURST_BUCKETS.length; i++) if (value <= BURST_BUCKETS[i]) burst.buckets[i]++;
  }

  /** The drain burst histogram in exposition format. Its duration includes intervening event-loop work. */
  burstMetrics() {
    const {buckets, sum, count} = this.#burst;
    const lines = [
      `# HELP ${BURST_NAME} Time from a native drain macrotask's start to the next setImmediate checkpoint, including the promise continuations it triggered`,
      `# TYPE ${BURST_NAME} histogram`,
    ];
    for (let i = 0; i < BURST_BUCKETS.length; i++)
      lines.push(`${BURST_NAME}_bucket{le="${BURST_BUCKETS[i]}"} ${buckets[i]}`);
    lines.push(`${BURST_NAME}_bucket{le="+Inf"} ${count}`, `${BURST_NAME}_sum ${sum}`, `${BURST_NAME}_count ${count}`);
    return `${lines.join("\n")}\n`;
  }
}
