// @ts-check
import assert from "node:assert/strict";
import {ActionQueue} from "./network-action-queue.js";
import {LogDelivery} from "./network-log-delivery.js";
import {CONTROL, FAILURES_MAX, SETTLE_CELLS, escalate} from "./network-turn-scheduler.js";

/**
 * @typedef {import("./network-turn-scheduler.js").Continuation} Continuation
 * @typedef {import("./network-runtime.js").NativeGossipHandle} Handle
 * @typedef {import("./network-runtime.js").NativeIncomingRequest} Incoming
 * @typedef {import("./network-runtime.js").NativeExchange} Exchange
 * @typedef {import("./network.js").NativeHost} Host
 * @typedef {import("./network.js").CloseResult} CloseResult
 * @typedef {import("./network.js").GossipJob} GossipJob
 * @typedef {import("./network.js").NativeForkEntry} NativeForkEntry
 * @typedef {import("./network.js").NativePeerAction} NativePeerAction
 * @typedef {import("./network.js").Verdict} Verdict
 * @typedef {import("./network-runtime.js").NativeNetworkApplicationRuntime} NativeNetworkApplicationRuntime
 * @typedef {import("./network-runtime.js").NativeEscalation} NativeEscalation
 * @typedef {import("./network-runtime.js").NativeGossipBatch} NativeGossipBatch
 * @typedef {import("./network-runtime.js").NativeGossipDependencyCheck} NativeGossipDependencyCheck
 * @typedef {import("./network-turn-scheduler.js").TurnScheduler} TurnScheduler
 * @typedef {import("./network-action-queue.js").CoalescedAction} CoalescedAction
 * @typedef {{failure: Error | null}} Terminal
 * @typedef {{resolve(): void, reject(error: unknown): void, remaining: number, weak: WeakRef<Settler> | null}} Settler
 * @typedef {{adopted: boolean, handles: Handle[], job: GossipJob | null, urgent: boolean}} Job
 * @typedef {{adopted: boolean, incoming: Incoming}} Start
 * @typedef {Pick<NativeNetworkApplicationRuntime, "exchange" | "fail" | "drainLogs"> & {
 * scheduler: TurnScheduler,
 * closed: Promise<CloseResult>,
 * close(): Promise<CloseResult>,
 * state: string
 * }} Runtime
 */

/** One turn's time budget; the rest yields to the next turn. */
export const BUDGET_MS = 8;
/** Serving capacity native accepts. */
const SERVING_MAX = 32;
/** Per-turn quotas of each payload source. */
export const QUOTAS = Object.freeze({bytes: 8 * 1024 * 1024, checks: 64, messages: 64, peers: 32, servingStarts: 8});
export const BURST_NAME = "lodestar_native_drain_burst_seconds";
export const BURST_BUCKETS = Object.freeze([0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2]);
const VERDICTS = new Set(["accept", "reject", "ignore"]);
const noop = () => undefined;
/**
 * Each report's settler, kept alive by the report itself. The pump also holds every unfinished settler while it lives;
 * once it is collected, only a report still reachable keeps its settler, and a promise derived from a report does not
 * keep the report.
 *
 * @type {WeakMap<Promise<void>, Settler>}
 */
const settlers = new WeakMap();

function closedError() {
  return Object.assign(new Error("NetworkClosed"), {code: "NetworkClosed"});
}

/** @param {string} callback */
function contractError(callback) {
  return Object.assign(new Error(`NativeHostContract: ${callback}`), {callback, code: "NativeHostContract"});
}

/** @param {Handle} handle */
function keyOf(handle) {
  return `${handle.index}:${handle.generation}`;
}

/**
 * The network's close result once the completion owner settled the runtime's close: the first failure, a delivery
 * failure or the owner's terminal error, whichever came first, even when a requested close was already underway; else
 * a requested close. It holds no host or pump reference, since the completion owner roots its reaction.
 *
 * @param {Promise<CloseResult>} closed
 * @param {Terminal} terminal
 * @returns {Promise<CloseResult>}
 */
export function closeResult(closed, terminal) {
  return closed.then((result) => {
    if (terminal.failure) return {error: terminal.failure, reason: "failed"};
    return result.reason === "failed" ? {error: result.error, reason: "failed"} : {reason: "requested"};
  });
}

/** The public view of a serving start: the native handle and retention stay with the binding. */
class IncomingRequest {
  #incoming;

  /** @param {Incoming} incoming */
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
  /**
   * @param {Uint8Array} data
   * @param {NativeForkEntry | null} context
   */
  respond(data, context) {
    return this.#incoming.respond(data, context);
  }
  finish() {
    return this.#incoming.finish();
  }
  /**
   * @param {number} status
   * @param {Uint8Array} message
   */
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
 * ordinary work, and after the retry timer while work waits for external capacity or a disabled service, or after
 * a failed turn. A null host capacity, or a closing facade, leaves settlement and acknowledgements only, until native
 * reports closed. A broken bridge contract escalates through native `fail`, which terminates the process.
 *
 * The runtime's scheduler and the closed observation hold the pump weakly, so a dropped facade and host can be collected.
 */
export class NativePump {
  /** @type {Runtime | null} */
  #runtime = null;
  /** @type {TurnScheduler | null} */
  #scheduler = null;
  #host;
  /** Terminal bookkeeping the facade shares; it holds no host reference. */
  #terminal;
  #weak = new WeakRef(this);
  #closing = false;
  #stopped = false;
  /** Consecutive exchanges that could not run. */
  #failures = 0;
  /** A delivery failure was arbitrated, and the host's `failed` received the first. */
  #arbitrated = false;
  #notified = false;
  #actions = new ActionQueue();
  /**
   * Delivered ordinary jobs a spent time budget left for the next turn, at most one batch.
   * @type {Job[]}
   */
  #heldJobs = [];
  /**
   * Delivered serving starts a spent time budget left for the next turn, at most one turn's quota.
   * @type {Incoming[]}
   */
  #heldStarts = [];
  /**
   * Each delivered message awaiting its owner disposition, by native handle.
   * @type {Map<string, Settler>}
   */
  #reported = new Map();
  /**
   * Each unsettled report's settler, held weakly: a report retained elsewhere settles at close although the pump and
   * host were collected, and one nobody retains roots neither its reactions nor the host they capture.
   *
   * @type {Set<WeakRef<Settler>>}
   */
  #unsettled = new Set();
  #burst = {buckets: new Array(BURST_BUCKETS.length).fill(0), count: 0, sum: 0};
  /** @type {LogDelivery | null} */
  #logs = null;
  /** Peer penalties dropped because the coalescing table was full. */
  get reportsDropped() {
    return this.#actions.reportsDropped;
  }

  /**
   * @param {Host} host
   * @param {Terminal} terminal
   */
  constructor(host, terminal) {
    this.#host = host;
    this.#terminal = terminal;
  }

  /**
   * Starts draining `runtime` on its scheduler, whose notifications call `request`, and delivering its log records.
   * @param {Runtime} runtime
   */
  attach(runtime) {
    this.#runtime = runtime;
    this.#scheduler = runtime.scheduler;
    this.#scheduler.bind(this);
    NativePump.#observe(this.#weak, this.#unsettled, runtime.closed);
    this.#logs = new LogDelivery(runtime, this.#host, /** @param {unknown} error */ (error) => this.#error(error));
    this.#logs.start();
  }

  /**
   * @param {WeakRef<NativePump>} weak
   * @param {Set<WeakRef<Settler>>} unsettled
   * @param {Promise<CloseResult>} closed
   */
  static #observe(weak, unsettled, closed) {
    const stop = () => {
      // Shutdown prevents the owner from disposing of whatever it has not acknowledged.
      const pending = [...unsettled];
      unsettled.clear();
      for (const settler of pending) settler.deref()?.reject(closedError());
      const pump = weak.deref();
      if (pump) pump.#stop();
    };
    closed.then(stop, stop);
  }

  /** A native notification, or capacity the host released. */
  request = () => this.#schedule();

  /** @param {Uint8Array} root */
  block(root) {
    this.#coalesce({root: new Uint8Array(root), type: "block"});
  }
  dropQueued() {
    this.#coalesce({type: "dropQueued"});
  }
  /**
   * @param {string} peerId
   * @param {NativePeerAction} action
   */
  reportPeer(peerId, action) {
    this.#coalesce({action, count: 1, peerId, type: "reportPeer"});
  }

  /**
   * Leaves settlement only: held serving starts are cancelled and held jobs ignored. Turns continue until native
   * reports closed. From a host callback, it also ends the delivery in progress.
   */
  close() {
    if (this.#closing) return;
    this.#closing = true;
    const starts = this.#heldStarts;
    const jobs = this.#heldJobs;
    this.#heldStarts = [];
    this.#heldJobs = [];
    for (const incoming of starts) void incoming.cancel().catch(noop);
    for (const job of jobs) this.#verdicts(job, null);
  }

  /**
   * Decides whether a delivery failure is the network's first, before cleanup whose native calls could record a later
   * owner failure: the first is the close result's error, and one that follows an owner failure goes to the error sink.
   *
   * @param {unknown} error
   */
  #arbitrate(error) {
    if (this.#stopped || this.#arbitrated) return;
    this.#arbitrated = true;
    const failure = error instanceof Error ? error : Object.assign(new Error("NativeHostFailure"), {cause: error});
    let ownerFailed = false;
    try {
      ownerFailed = this.#runtime?.state === "failed";
    } catch {
      // A runtime without state has closed.
    }
    if (ownerFailed) this.#error(failure);
    else this.#terminal.failure = failure;
  }

  /**
   * After an arbitrated failure and the delivery's cleanup: payload delivery stops while settlement continues, and a
   * first failure reaches the host's `failed` once, so the host can finish bounded cleanup before it closes.
   */
  #fail() {
    if (this.#stopped) return;
    this.close();
    const failure = this.#terminal.failure;
    if (failure === null || this.#notified) return;
    this.#notified = true;
    try {
      this.#host.failed(failure);
    } catch (thrown) {
      // A host that cannot clean up leaves nothing to wait for.
      this.#error(thrown);
      try {
        this.#runtime?.close();
      } catch {
        // A runtime that cannot close is already closing.
      }
    }
  }

  /**
   * An operational failure the pump recovered from, for the host to log.
   * @param {unknown} error
   */
  #error(error) {
    try {
      this.#host.error?.(error);
    } catch {
      // Reporting a recovered failure must not stop the pump.
    }
  }

  /** @param {CoalescedAction} action */
  #coalesce(action) {
    if (this.#stopped) return;
    this.#actions.enqueue(action);
    this.#schedule();
  }

  #schedule() {
    if (!this.#stopped) this.#scheduler?.schedule();
  }

  #stop() {
    this.#stopped = true;
    this.#scheduler?.stop();
    this.close();
    // Native keeps its records past close, so the last ones, the shutdown's included, still reach the host.
    this.#logs?.stop();
  }

  /**
   * @param {NativeEscalation} site
   * @param {unknown} cause
   * @returns {never}
   */
  #escalate(site, cause) {
    this.#stop();
    assert(this.#runtime !== null);
    escalate(this.#runtime, site, cause);
  }

  /**
   * One of the runtime's turns. Returns when the next is due: now, later, on the retry timer, or idle.
   * @returns {Continuation}
   */
  turn() {
    if (this.#stopped) return "idle";
    const started = performance.now();
    try {
      const next = this.#turn(started + BUDGET_MS);
      // Actions queued while the turn ran need one too, unless its exchange failed.
      return next !== "retry" && this.#actions.pending() ? "now" : next;
    } finally {
      // The burst end is queued first, so it covers only this turn.
      setImmediate(NativePump.#burstEnd, this.#weak, started);
    }
  }

  /**
   * The host's demand for this turn, or null for settlement only. Throws what the host's capacity read threw.
   * @param {number} deadline
   */
  #demand(deadline) {
    if (this.#closing) return null;
    const capacity = this.#host.capacity();
    // The host may close the network from its capacity read.
    if (capacity === null || this.#closing) return null;
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

  /**
   * @param {number} deadline
   * @returns {Continuation}
   */
  #turn(deadline) {
    assert(this.#runtime !== null);
    let demand = null;
    let capacityFailed = false;
    try {
      demand = this.#demand(deadline);
    } catch (error) {
      // The turn still settles control; the capacity read retries on the timer.
      capacityFailed = true;
      this.#error(error);
    }
    const batch = this.#actions.take();
    let result;
    try {
      result = this.#runtime.exchange(batch, demand ?? CONTROL);
    } catch (error) {
      // Native refuses only an invalid batch or a nested exchange, so a refusal of this generated batch is a
      // broken contract. Anything else left native untouched: the batch requeues and the turn retries.
      const code = error && typeof error === "object" && "code" in error ? error.code : undefined;
      if (typeof code === "string") this.#escalate("generated_batch", code);
      this.#actions.restore(batch);
      if (++this.#failures >= FAILURES_MAX) this.#escalate("failed_turns", error);
      this.#error(error);
      return "retry";
    }
    this.#failures = 0;
    this.#acknowledge(result.acknowledged);
    let held = false;
    // A serving start native could not hand over is decided before delivery and its cleanup.
    let deliveryFailed = result.failure !== null;
    if (deliveryFailed) this.#arbitrate(result.failure);
    try {
      if (demand !== null) held = this.#deliver(result, deadline);
    } catch {
      // The delivery arbitrated it before its cleanup.
      deliveryFailed = true;
    }
    // Ordinary work the time budget left unclaimed waits for the next turn, as held jobs do.
    const budgetEnded = demand !== null && demand.messages > 0 && !demand.claimOrdinary;
    /** @type {Continuation} */
    let next = "idle";
    if (result.more || held || (budgetEnded && result.disabledWaiting)) next = "now";
    else if (capacityFailed || result.parked.serving || result.parked.ordinary || result.disabledWaiting)
      next = "later";
    if (deliveryFailed) this.#fail();
    return next;
  }

  /**
   * Resolves each job whose every message the owner has now disposed of.
   * @param {readonly Handle[]} acknowledged
   */
  #acknowledge(acknowledged) {
    for (const handle of acknowledged ?? []) {
      const key = keyOf(handle);
      const job = this.#reported.get(key);
      if (!job) continue;
      this.#reported.delete(key);
      if (--job.remaining > 0) continue;
      if (job.weak) this.#unsettled.delete(job.weak);
      job.resolve();
    }
  }

  /**
   * Hands one exchange's delivery to the host: peers, then serving starts, then dependency checks, then gossip jobs.
   * If the host's peer handler throws, or the host closes the network, the delivery stops there and the pump retires
   * what it never handed over: every job gets an ignore verdict, every serving start is cancelled once and every check
   * is classified unavailable. Returns whether delivered work waits for the next turn.
   *
   * @param {Exchange} result
   * @param {number} deadline
   */
  #deliver(result, deadline) {
    const jobs = this.#jobs(result.gossip);
    const starts = result.serving.map((incoming) => ({adopted: false, incoming}));
    const checks = result.checks;
    let checked = checks.length === 0;
    try {
      // Host code may already have run within the exchange's settlements.
      if (this.#closing) return false;
      if (result.peers.length > 0) this.#host.peers(result.peers);
      if (this.#closing) return false;
      const heldStarts = this.#start(starts, deadline);
      if (this.#closing) return false;
      this.#check(checks);
      checked = true;
      if (this.#closing) return false;
      return this.#dispatch(jobs, deadline) || heldStarts;
    } catch (error) {
      // Decided before the cleanup below, whose cancellations reach native and could record a later owner failure.
      this.#arbitrate(error);
      throw error;
    } finally {
      for (const job of jobs) if (!job.adopted) this.#verdicts(job, null);
      for (const start of starts) if (!start.adopted) void start.incoming.cancel().catch(noop);
      if (!checked) for (const {handle} of checks) this.#actions.enqueue({available: false, handle, type: "classify"});
    }
  }

  /**
   * Jobs with host records that physically omit native handles, each awaiting every message's disposition.
   * @param {NativeGossipBatch | null} gossip
   * @returns {Job[]}
   */
  #jobs(gossip) {
    if (!gossip) return [];
    return gossip.jobs.map(({kind, grouped, urgent, start, length}) => {
      const natives = gossip.messages.slice(start, start + length);
      /** @type {PromiseWithResolvers<void>} */
      const {promise: reported, resolve, reject} = Promise.withResolvers();
      // A host that does not await a job's disposition sees no unhandled rejection at shutdown.
      reported.catch(noop);
      /** @type {Settler} */
      const settle = {reject, remaining: natives.length, resolve, weak: null};
      settle.weak = new WeakRef(settle);
      settlers.set(reported, settle);
      this.#unsettled.add(settle.weak);
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
   *
   * @param {Start[]} starts
   * @param {number} deadline
   */
  #start(starts, deadline) {
    const pending = this.#heldStarts;
    this.#heldStarts = [];
    for (const start of starts) {
      start.adopted = true;
      pending.push(start.incoming);
    }
    // Starts after a serve that closed the network are cancelled instead.
    for (const [index, incoming] of pending.entries()) {
      if (this.#closing) void incoming.cancel().catch(noop);
      else {
        if (performance.now() >= deadline) {
          this.#heldStarts = pending.slice(index);
          return true;
        }
        this.#serve(incoming);
      }
    }
    return false;
  }

  /**
   * Hands one serving start to the host. Its serving capacity stays charged until the host's promise settles, which
   * the binding registers before host code runs. A throw or rejection fails the stream.
   *
   * @param {Incoming} incoming
   */
  #serve(incoming) {
    /** @type {PromiseWithResolvers<void>} */
    const {promise: retired, resolve: release} = Promise.withResolvers();
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

  /**
   * @param {WeakRef<NativePump>} weak
   * @param {Promise<void>} served
   * @param {Incoming} incoming
   * @param {() => void} release
   */
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

  /**
   * Classifies every check with the host's answers, or unavailable when it cannot answer them all.
   * @param {readonly NativeGossipDependencyCheck[]} checks
   */
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
      this.#actions.enqueue({available: available?.[i] === true, handle, type: "classify"});
  }

  /**
   * Starts every urgent job now, whatever the budget, and queues ordinary jobs, which start until `deadline`: at least
   * one per turn unless the budget was spent before this delivery and no job was held. Returns whether jobs wait.
   *
   * @param {Job[]} jobs
   * @param {number} deadline
   */
  #dispatch(jobs, deadline) {
    // Ordinary work delivered at the turn's start is new work, which a spent budget defers like the claim it replaced.
    const progress = this.#heldJobs.length > 0 || performance.now() < deadline;
    // Jobs arrive in priority order, so urgent jobs start first and none waits for the budget. A validation that
    // closes the network leaves the rest to the delivery's cleanup, and held jobs to close.
    for (const job of jobs) {
      if (this.#closing) break;
      job.adopted = true;
      if (job.urgent) this.#validate(job);
      else this.#heldJobs.push(job);
    }
    let started = 0;
    while (this.#heldJobs.length > 0 && !this.#closing) {
      if ((started > 0 || !progress) && performance.now() >= deadline) break;
      started++;
      const job = this.#heldJobs.shift();
      assert(job !== undefined);
      this.#validate(job);
    }
    return this.#heldJobs.length > 0;
  }

  /**
   * Hands one job to the host. A throw, a rejection or the wrong verdicts ignore every message.
   * @param {Job} record
   */
  #validate(record) {
    const {job} = record;
    assert(job !== null);
    record.job = null;
    let verdicts;
    try {
      verdicts = Promise.resolve(this.#host.validate(job));
    } catch (error) {
      verdicts = Promise.reject(error);
    }
    NativePump.#validated(this.#weak, verdicts, record);
  }

  /**
   * @param {WeakRef<NativePump>} weak
   * @param {Promise<readonly Verdict[]>} verdicts
   * @param {Job} record
   */
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

  /**
   * Queues one verdict per message, in order; anything but one valid verdict per message ignores them all.
   * @param {Job} record
   * @param {unknown} values
   */
  #verdicts(record, values) {
    if (this.#stopped) return;
    const count = record.handles.length;
    const valid =
      Array.isArray(values) && values.length === count && record.handles.every((_, i) => VERDICTS.has(values[i]));
    if (values !== null && !valid) this.#error(contractError("validate"));
    for (let i = 0; i < count; i++)
      this.#actions.enqueue({handle: record.handles[i], type: "verdict", verdict: valid ? values[i] : "ignore"});
    this.#schedule();
  }

  /**
   * @param {WeakRef<NativePump>} weak
   * @param {number} started
   */
  static #burstEnd(weak, started) {
    const pump = weak.deref();
    if (!pump) return;
    const value = (performance.now() - started) / 1000;
    const burst = pump.#burst;
    burst.count++;
    burst.sum += value;
    for (let i = 0; i < BURST_BUCKETS.length; i++) if (value <= BURST_BUCKETS[i]) burst.buckets[i]++;
  }

  /**
   * The drain burst histogram, whose duration includes intervening event-loop work, and separate counters for
   * undelivered log records and failed log drains, in exposition format.
   */
  metrics() {
    const {buckets, sum, count} = this.#burst;
    const lines = [
      `# HELP ${BURST_NAME} Time from a native drain macrotask's start to the next setImmediate checkpoint, including the promise continuations it triggered`,
      `# TYPE ${BURST_NAME} histogram`,
    ];
    for (let i = 0; i < BURST_BUCKETS.length; i++)
      lines.push(`${BURST_NAME}_bucket{le="${BURST_BUCKETS[i]}"} ${buckets[i]}`);
    lines.push(`${BURST_NAME}_bucket{le="+Inf"} ${count}`, `${BURST_NAME}_sum ${sum}`, `${BURST_NAME}_count ${count}`);
    assert(this.#logs !== null);
    return `${lines.join("\n")}\n${this.#logs.metrics()}`;
  }
}
