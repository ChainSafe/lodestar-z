import {afterEach, describe, expect, it, vi} from "vitest";
import type {
  DependencyCheck,
  GossipJob,
  IncomingRequest,
  NativeLogLoss,
  NativeLogRecord,
  NativePeerObservation,
  NativeTopicKind,
  Verdict,
} from "../src/network.js";
import {ACTION_MAX, BUDGET_MS, BURST_NAME, NativePump, closeResult} from "../src/network-pump.js";
import type {
  NativeAction,
  NativeExchange,
  NativeExchangeDemand,
  NativeGossipBatch,
  NativeGossipDependencyCheck,
  NativeGossipHandle,
  NativeGossipMessage,
  NativeIncomingRequest,
  NativeLogBatch,
} from "../src/network-runtime.js";
import {TurnScheduler} from "../src/network-turn-scheduler.js";
import {childTestTimeout, spawnChild} from "./utils/network.js";
import {Escalated, immediates, runUntilEscalated} from "./utils/network-turn-scheduler.js";

const MIB = 1024 * 1024;
const full: NativeExchangeDemand = {
  bytes: 8 * MIB,
  capacity: {ordinary: true, serving: 32},
  checks: 64,
  claimOrdinary: true,
  messages: 64,
  peers: 32,
  servingStarts: 8,
  settleCells: 32,
};
const control: NativeExchangeDemand = {
  bytes: 0,
  capacity: null,
  checks: 0,
  claimOrdinary: false,
  messages: 0,
  peers: 0,
  servingStarts: 0,
  settleCells: 32,
};
const idle: NativeExchange = {
  acknowledged: [],
  checks: [],
  closed: null,
  completions: [],
  disabledWaiting: false,
  failure: null,
  gossip: null,
  more: false,
  parked: {ordinary: false, serving: false},
  peers: [],
  serving: [],
};
const handle = (index: number, generation = 1n): NativeGossipHandle => ({generation, index});
/** Each fixture's native close, which the test may leave pending. */
const running: {resolve(result: {reason: "requested"}): void}[] = [];
/** The pump's log delivery timer, armed until native closes. */
const LOG_TIMER = 1;
const noLogs = {dropped: 0n, more: false, records: [], suppressed: 0n, truncated: 0n};

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return {promise, reject, resolve};
}

function macrotask(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

function message(index: number, generation = 1n): NativeGossipMessage {
  return {
    attestationData: null,
    connection: {generation: 1, index: 0},
    data: new Uint8Array(4).fill(index),
    handle: handle(index, generation),
    id: new Uint8Array(20).fill(index),
    peerId: "peer",
    receivedAtUnixMs: 12345,
    slot: 7n,
    topic: "topic",
  };
}

type JobSpec = {messages: number[]; urgent?: boolean; grouped?: boolean; kind?: NativeTopicKind; generation?: bigint};

/** One batch of jobs, each listing its messages' cell indexes, in priority order. */
function gossip(...specs: JobSpec[]): NativeGossipBatch {
  const messages: NativeGossipMessage[] = [];
  const jobs = specs.map(({messages: indexes, urgent = false, grouped = false, kind, generation}) => {
    const start = messages.length;
    messages.push(...indexes.map((index) => message(index, generation)));
    return {
      grouped,
      kind: kind ?? (urgent ? "beacon_block" : grouped ? "beacon_attestation" : "voluntary_exit"),
      length: indexes.length,
      start,
      urgent,
    };
  });
  return {jobs, messages};
}

function check(index: number): NativeGossipDependencyCheck {
  return {handle: handle(index), peerId: "peer", root: new Uint8Array(32).fill(index), slot: 3n, topic: "topic"};
}

function incoming(name = "start") {
  const closed = deferred<void>();
  const request = {
    cancel: vi.fn(() => Promise.resolve()),
    closed: closed.promise,
    connection: {generation: 1, index: 1},
    data: new Uint8Array(8),
    fail: vi.fn((_status: number, _message: Uint8Array) => Promise.resolve()),
    finish: vi.fn(() => Promise.resolve()),
    name,
    peerId: "peer",
    protocol: "/eth2/beacon_chain/req/ping/1/ssz_snappy",
    ready: vi.fn(() => Promise.resolve()),
    respond: vi.fn(() => Promise.resolve()),
    retainUntil: vi.fn((_retired: Promise<void>): void => undefined),
  };
  return request;
}
type Incoming = ReturnType<typeof incoming>;

const peerEvent: NativePeerObservation = {
  connection: {generation: 1, index: 0},
  identity: "peer",
  ownerSequence: 1n,
  reason: "host",
  type: "closed",
};

function fixture() {
  let now = 0;
  vi.spyOn(performance, "now").mockImplementation(() => now);
  const closed = deferred<{reason: "requested"} | {reason: "failed"; error: Error}>();
  running.push(closed);
  const runtime = {
    close: vi.fn(() => closed.promise),
    closed: closed.promise,
    drainLogs: vi.fn((_max: number): NativeLogBatch => noLogs),
    exchange: vi.fn((_actions: readonly NativeAction[], _demand: NativeExchangeDemand): NativeExchange => idle),
    fail: vi.fn((site: string, _reason: string): never => {
      throw new Escalated(site);
    }),
    scheduler: null as unknown,
    state: "running",
  };
  // The pump outlives every test, so its turns never drain without it.
  runtime.scheduler = new TurnScheduler(runtime);
  const host = {
    capacity: vi.fn((): {ordinary: boolean; serving: number} | null => ({ordinary: true, serving: 32})),
    checkDependencies: vi.fn((checks: readonly DependencyCheck[]): readonly boolean[] => checks.map(() => true)),
    error: vi.fn((_error: unknown): void => undefined),
    failed: vi.fn((_error: Error): void => undefined),
    logs: vi.fn((_records: readonly NativeLogRecord[], _lost: NativeLogLoss | null): void => undefined),
    peers: vi.fn((_events: readonly NativePeerObservation[]): void => undefined),
    serve: vi.fn((_request: IncomingRequest): Promise<void> => Promise.resolve()),
    validate: vi.fn(
      (job: GossipJob): Promise<readonly Verdict[]> => Promise.resolve(job.messages.map(() => "accept" as const))
    ),
  };
  const terminal: {failure: Error | null} = {failure: null};
  const pump = new NativePump(host, terminal);
  pump.attach(runtime);
  return {
    actions: (i: number) => runtime.exchange.mock.calls[i][0],
    advance(ms: number) {
      now += ms;
    },
    /** Actions and demand of each exchange. */
    calls: () => runtime.exchange.mock.calls,
    closed,
    host,
    get now() {
      return now;
    },
    pump,
    runtime,
    terminal,
  };
}

afterEach(async () => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  // Native closes under every pump a test left running, which stops its log timer before a later test fakes timers.
  for (const closed of running.splice(0)) closed.resolve({reason: "requested"});
  await macrotask();
});

describe("binding pump scheduling", () => {
  it.each(["Uint8Array", "Buffer"])("copies queued roots from a reused %s", async (kind) => {
    const node = fixture();
    const root = kind === "Buffer" ? Buffer.alloc(32, 1) : new Uint8Array(32).fill(1);
    node.pump.block(root);
    root.fill(2);
    node.pump.block(root);
    root.fill(3);
    await macrotask();
    expect(node.actions(0)).toEqual([
      {root: new Uint8Array(32).fill(1), type: "block"},
      {root: new Uint8Array(32).fill(2), type: "block"},
    ]);
  });

  it("keeps a queued root after the caller transfers its buffer", async () => {
    const node = fixture();
    const root = new Uint8Array(32).fill(7);
    node.pump.block(root);
    structuredClone(root, {transfer: [root.buffer]});
    await macrotask();
    expect(node.actions(0)).toEqual([{root: new Uint8Array(32).fill(7), type: "block"}]);
  });

  it("only schedules on notification and makes one exchange per turn", async () => {
    const node = fixture();
    node.pump.request();
    node.pump.request();
    expect(node.runtime.exchange).not.toHaveBeenCalled();
    await macrotask();
    expect(node.host.capacity).toHaveBeenCalledOnce();
    expect(node.runtime.exchange).toHaveBeenCalledExactlyOnceWith([], full);
    for (const callback of ["validate", "checkDependencies", "serve", "peers"] as const)
      expect(node.host[callback]).not.toHaveBeenCalled();
    await macrotask();
    expect(node.runtime.exchange).toHaveBeenCalledOnce();
  });

  it("passes the host's capacity bounded by native's, and a null capacity leaves settlement only", async () => {
    const node = fixture();
    node.host.capacity.mockReturnValueOnce({ordinary: false, serving: 40.5}).mockReturnValueOnce(null);
    node.pump.request();
    await macrotask();
    node.runtime.exchange.mockReturnValueOnce({...idle, checks: [check(1)], peers: [peerEvent]});
    node.pump.request();
    await macrotask();
    expect(node.calls()).toEqual([
      [[], {...full, capacity: {ordinary: false, serving: 32}}],
      [[], control],
    ]);
    // Control-only draining hands the host nothing.
    expect(node.host.peers).not.toHaveBeenCalled();
    expect(node.host.checkDependencies).not.toHaveBeenCalled();
  });

  it("turns again at once for held jobs, and yields them to the time budget", async () => {
    const node = fixture();
    node.host.validate.mockImplementation(() => {
      node.advance(BUDGET_MS);
      return new Promise(() => undefined);
    });
    node.runtime.exchange.mockReturnValueOnce({...idle, gossip: gossip({messages: [1]}, {messages: [2]})});
    node.pump.request();
    await macrotask();
    expect(node.host.validate).toHaveBeenCalledOnce();
    await macrotask();
    expect(node.runtime.exchange).toHaveBeenCalledTimes(2);
    // Held jobs withhold the claim, and the held job starts.
    expect(node.calls()[1][1]).toMatchObject({claimOrdinary: false});
    expect(node.host.validate).toHaveBeenCalledTimes(2);
    await macrotask();
    expect(node.runtime.exchange).toHaveBeenCalledTimes(2);
  });

  it("turns again at once when the time budget left ordinary work unclaimed", async () => {
    const node = fixture();
    node.host.capacity.mockImplementationOnce(() => {
      node.advance(BUDGET_MS);
      return {ordinary: true, serving: 32};
    });
    node.runtime.exchange.mockReturnValueOnce({...idle, disabledWaiting: true});
    node.pump.request();
    await macrotask();
    await macrotask();
    expect(node.calls().map(([, demand]) => demand.claimOrdinary)).toEqual([false, true]);
    await macrotask();
    expect(node.runtime.exchange).toHaveBeenCalledTimes(2);
  });

  it("a serving capacity of 32 under a quota of 8 takes four immediate turns and no timer", async () => {
    vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
    const node = fixture();
    for (let i = 0; i < 3; i++) node.runtime.exchange.mockReturnValueOnce({...idle, more: true});
    node.pump.request();
    for (let i = 0; i < 5; i++) await macrotask();
    expect(node.runtime.exchange).toHaveBeenCalledTimes(4);
    expect(vi.getTimerCount()).toBe(LOG_TIMER);
  });

  it("retries parked external capacity on the single timer until capacity returns", async () => {
    vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
    const node = fixture();
    const parked = {...idle, parked: {ordinary: true, serving: true}};
    node.runtime.exchange.mockReturnValueOnce(parked).mockReturnValueOnce(parked);
    node.pump.request();
    await macrotask();
    expect(vi.getTimerCount()).toBe(LOG_TIMER + 1);
    // Another request does not add a timer.
    node.pump.request();
    await macrotask();
    expect(vi.getTimerCount()).toBe(LOG_TIMER + 1);
    vi.advanceTimersByTime(25);
    await macrotask();
    expect(node.runtime.exchange).toHaveBeenCalledTimes(3);
    expect(vi.getTimerCount()).toBe(LOG_TIMER);
    expect(node.runtime.fail).not.toHaveBeenCalled();
  });

  it("settles only after close, retrying disabled payload on the timer, until native reports closed", async () => {
    vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
    const node = fixture();
    node.pump.close();
    node.runtime.exchange.mockReturnValueOnce({...idle, more: true}).mockReturnValue({...idle, disabledWaiting: true});
    node.pump.request();
    for (let i = 0; i < 3; i++) await macrotask();
    expect(node.calls()).toEqual([
      [[], control],
      [[], control],
    ]);
    expect(vi.getTimerCount()).toBe(LOG_TIMER + 1);
    node.closed.resolve({reason: "requested"});
    await macrotask();
    expect(vi.getTimerCount()).toBe(0);
    node.pump.request();
    node.pump.reportPeer("peer", "fatal");
    await macrotask();
    expect(node.runtime.exchange).toHaveBeenCalledTimes(2);
    expect(node.host.capacity).not.toHaveBeenCalled();
  });

  it("sends obligations first, 256 per exchange, and coalesces blocks, rechecks and peer penalties", async () => {
    const node = fixture();
    const captured: NativeAction[][] = [];
    node.runtime.exchange.mockImplementation((actions) => {
      captured.push([...actions]);
      return idle;
    });
    node.runtime.exchange.mockImplementationOnce((actions) => {
      captured.push([...actions]);
      return {...idle, gossip: gossip({grouped: true, messages: Array.from({length: 1000}, (_, i) => i)})};
    });
    node.pump.request();
    await macrotask();
    // The job's verdicts are queued; requests arriving now queue behind them.
    node.pump.block(new Uint8Array(32).fill(1));
    node.pump.block(new Uint8Array(32).fill(1));
    for (let i = 0; i < 150; i++) node.pump.reportPeer("peer", "high_tolerance");
    node.pump.reportPeer("peer", "fatal");
    node.pump.dropQueued();
    for (let i = 0; i < 6; i++) await macrotask();
    expect(captured.map((actions) => actions.length)).toEqual([0, ACTION_MAX, ACTION_MAX, ACTION_MAX, 1000 - 768 + 4]);
    expect(captured.slice(1, 4).every((actions) => actions.every(({type}) => type === "verdict"))).toBe(true);
    expect(captured[1][0]).toEqual({handle: handle(0), type: "verdict", verdict: "accept"});
    expect(captured[4].slice(1000 - 768)).toEqual([
      {root: new Uint8Array(32).fill(1), type: "block"},
      {action: "high_tolerance", count: 100, peerId: "peer", type: "reportPeer"},
      {action: "fatal", count: 1, peerId: "peer", type: "reportPeer"},
      {type: "dropQueued"},
    ]);
    // Roots past the coalescing bound become one recheck of every waiting message.
    for (let i = 0; i < 257; i++) node.pump.block(Uint8Array.of(i >> 8, i & 255));
    node.pump.block(new Uint8Array(32).fill(2));
    await macrotask();
    expect(captured.at(-1)).toEqual([{type: "recheck"}]);
  });

  it("drops peer penalties past 512 coalesced entries and counts them", async () => {
    const node = fixture();
    for (let i = 0; i < 514; i++) node.pump.reportPeer(`peer-${i}`, "fatal");
    expect(node.pump.reportsDropped).toBe(2);
    await macrotask();
    expect(node.actions(0)).toHaveLength(ACTION_MAX);
    await macrotask();
    expect(node.actions(1)).toHaveLength(512 - ACTION_MAX);
  });

  it("keeps a penalty reported while its batch is in flight for the next exchange", async () => {
    const node = fixture();
    // Legacy settlement can run a promise's `then` getter inside the exchange, which may report the same peer.
    node.runtime.exchange.mockImplementationOnce(() => {
      node.pump.reportPeer("peer", "fatal");
      return idle;
    });
    node.pump.reportPeer("peer", "fatal");
    await macrotask();
    await macrotask();
    const report = {action: "fatal", count: 1, peerId: "peer", type: "reportPeer"};
    expect(node.calls().map(([actions]) => actions)).toEqual([[report], [report]]);
  });

  it("escalates a batch native refuses", () => {
    const node = fixture();
    const queued = immediates();
    const refusal = Object.assign(new Error("InvalidNetworkActions"), {code: "InvalidNetworkActions"});
    node.runtime.exchange.mockImplementationOnce(() => {
      throw refusal;
    });
    node.pump.request();
    expect(() => queued.shift()?.()).toThrow(Escalated);
    expect(node.runtime.fail).toHaveBeenCalledExactlyOnceWith("generated_batch", "InvalidNetworkActions");
  });

  it.each([
    [
      "throws",
      () => {
        throw new Error("capacity failed");
      },
    ],
    ["breaks its contract", () => ({ordinary: "yes", serving: 1})],
  ])("pauses payload delivery when capacity %s while continuing settlement and timed retries", (_, read) => {
    vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
    const node = fixture();
    const queued = immediates();
    node.host.capacity.mockImplementation(read as unknown as () => null);
    node.pump.request();
    expect(runUntilEscalated(queued, 30)).toBe(false);
    expect(node.calls().length).toBeGreaterThanOrEqual(5);
    for (const call of node.calls()) expect(call).toEqual([[], control]);
    expect(node.host.error).toHaveBeenCalledTimes(node.calls().length);
    expect(node.host.peers).not.toHaveBeenCalled();
    expect(node.host.serve).not.toHaveBeenCalled();
    expect(node.host.failed).not.toHaveBeenCalled();
    expect(node.runtime.fail).not.toHaveBeenCalled();
  });

  it("acknowledges admitted work while capacity fails, resumes serving on recovery, and clears retries on close", async () => {
    vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
    const node = fixture();
    node.runtime.exchange.mockImplementation((actions) => ({
      ...idle,
      acknowledged: actions.flatMap((action) => (action.type === "verdict" ? [action.handle] : [])),
    }));
    node.runtime.exchange.mockReturnValueOnce({...idle, gossip: gossip({messages: [1]})});
    node.pump.request();
    await macrotask();
    const job = node.host.validate.mock.calls[0][0];
    const failure = new Error("capacity failed");
    node.host.capacity.mockImplementation(() => {
      throw failure;
    });
    for (let i = 0; i < 6; i++) {
      vi.advanceTimersByTime(25);
      await macrotask();
    }
    await expect(job.reported).resolves.toBeUndefined();
    expect(node.host.error.mock.calls.length).toBeGreaterThanOrEqual(5);
    expect(node.host.failed).not.toHaveBeenCalled();
    expect(node.runtime.fail).not.toHaveBeenCalled();
    expect(node.host.validate).toHaveBeenCalledOnce();
    const start = incoming();
    node.host.capacity.mockReturnValue({ordinary: true, serving: 32});
    node.runtime.exchange.mockReturnValueOnce({...idle, serving: [start]});
    node.pump.request();
    await macrotask();
    expect(node.host.serve).toHaveBeenCalledOnce();
    expect(start.cancel).not.toHaveBeenCalled();
    node.host.capacity.mockImplementation(() => {
      throw failure;
    });
    node.pump.close();
    node.closed.resolve({reason: "requested"});
    await macrotask();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("successful settlement resets exchange failures even while capacity remains unavailable", () => {
    vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
    const node = fixture();
    const queued = immediates();
    node.host.capacity.mockImplementation(() => {
      throw new Error("capacity failed");
    });
    const failure = new Error("exchange failed");
    const results = [failure, {...idle, more: true}, failure, {...idle, more: true}, failure, idle];
    node.runtime.exchange.mockImplementation(() => {
      const result = results.shift() ?? idle;
      if (result instanceof Error) throw result;
      return result;
    });
    node.pump.request();
    expect(runUntilEscalated(queued, 40)).toBe(false);
    expect(node.runtime.exchange.mock.calls.length).toBeGreaterThanOrEqual(6);
    expect(node.runtime.fail).not.toHaveBeenCalled();
  });

  it("still escalates consecutive exchange failures when capacity also fails", () => {
    vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
    const node = fixture();
    const queued = immediates();
    node.host.capacity.mockImplementation(() => {
      throw new Error("capacity failed");
    });
    node.runtime.exchange.mockImplementation(() => {
      throw new Error("exchange failed");
    });
    node.pump.request();
    expect(runUntilEscalated(queued, 20)).toBe(true);
    expect(node.host.capacity).toHaveBeenCalledTimes(3);
    expect(node.runtime.exchange).toHaveBeenCalledTimes(3);
    expect(node.runtime.fail).toHaveBeenCalledExactlyOnceWith("failed_turns", "exchange failed");
  });

  it("after close, an exchange that settles ends a run of failed ones", () => {
    vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
    const node = fixture();
    const queued = immediates();
    node.pump.close();
    const failure = new Error("exchange failed");
    const results = [failure, {...idle, more: true}, failure, {...idle, more: true}, failure, idle];
    node.runtime.exchange.mockImplementation(() => {
      const result = results.shift() ?? idle;
      if (result instanceof Error) throw result;
      return result;
    });
    node.pump.request();
    expect(runUntilEscalated(queued, 40)).toBe(false);
    expect(node.runtime.exchange).toHaveBeenCalledTimes(6);
    expect(node.host.error).toHaveBeenCalledTimes(3);
  });

  it("a throw before phase B leaves the batch queued and retries on the timer", async () => {
    vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
    const node = fixture();
    node.host.checkDependencies.mockReturnValueOnce([false]);
    const failure = new Error("exchange failed");
    node.runtime.exchange
      .mockImplementationOnce(() => {
        node.pump.reportPeer("peer", "fatal");
        return {...idle, checks: [check(3)]};
      })
      .mockImplementationOnce(() => {
        throw failure;
      });
    node.pump.request();
    await macrotask();
    await macrotask();
    expect(node.host.error).toHaveBeenCalledExactlyOnceWith(failure);
    expect(vi.getTimerCount()).toBe(LOG_TIMER + 1);
    vi.advanceTimersByTime(25);
    await macrotask();
    expect(node.actions(2)).toEqual([
      {available: false, handle: handle(3), type: "classify"},
      {action: "fatal", count: 1, peerId: "peer", type: "reportPeer"},
    ]);
    expect(node.runtime.fail).not.toHaveBeenCalled();
  });

  it("a failed exchange keeps the process alive on its timer, also after close, which parked work does not", async () => {
    const timers: NodeJS.Timeout[] = [];
    const schedule = setTimeout;
    vi.spyOn(globalThis, "setTimeout").mockImplementation(((...args: Parameters<typeof setTimeout>) => {
      const timer = schedule(...args);
      // The pump's retry timer.
      if (args[1] === 25) timers.push(timer);
      return timer;
    }) as typeof setTimeout);
    const node = fixture();
    node.runtime.exchange.mockReturnValueOnce({...idle, parked: {ordinary: false, serving: true}});
    node.pump.request();
    await macrotask();
    expect(timers.map((timer) => timer.hasRef())).toEqual([false]);
    clearTimeout(timers[0]);
    node.closed.resolve({reason: "requested"});
    await macrotask();

    const closing = fixture();
    closing.pump.close();
    closing.runtime.exchange.mockImplementationOnce(() => {
      throw new Error("exchange failed");
    });
    closing.pump.request();
    await macrotask();
    expect(timers.slice(1).map((timer) => timer.hasRef())).toEqual([true]);
    closing.closed.resolve({reason: "requested"});
    await macrotask();
  });

  it(
    "a close whose exchanges keep failing, with nothing else alive, settles or escalates in a child process",
    childTestTimeout(),
    () => {
      // The parent enforces the deadline; exiting without the close result or the trigger-3 abort is the regression.
      const child = spawnChild(["--import", "tsx", "bindings/test/fixtures/network-shutdown-retry.mjs"]);
      const closed = child.status === 0 && child.stdout.includes("closed");
      const escalated =
        child.signal === "SIGABRT" && child.stderr.includes("native network bridge failed_turns: exchange failed");
      expect(
        closed || escalated,
        JSON.stringify({signal: child.signal, status: child.status, stdout: child.stdout})
      ).toBe(true);
    }
  );

  it.each([
    ["generated_batch", "generated_batch", "InvalidNetworkInteger"],
    ["failed_turns", "failed_turns", "exchange failed"],
    ["completion_contract", "completion_contract", "completed publication 0:1"],
    ["close_missing", "completion_contract", "closed with records unsettled: 1"],
  ])(
    "raising %s over a real native runtime terminates the process through native fail, in a child process",
    childTestTimeout(),
    (scenario, site, reason) => {
      const child = spawnChild(["--import", "tsx", "bindings/test/fixtures/network-escalation.mjs", scenario]);
      expect(child.signal, child.stderr).toBe("SIGABRT");
      expect(child.stdout).not.toContain("survived");
      expect(child.stderr).toContain(`FATAL ERROR: native network bridge ${site}: ${reason}\n`);
    }
  );

  it(
    "a real runtime settles commands through capacity failures, recovers, and closes normally",
    childTestTimeout(),
    () => {
      const child = spawnChild([
        "--import",
        "tsx",
        "bindings/test/fixtures/network-escalation.mjs",
        "capacity_recovery",
      ]);
      expect(child.status, child.stderr).toBe(0);
      expect(child.signal, child.stderr).toBeNull();
      expect(child.stdout).toContain("capacity recovered; identity settled; closed");
      expect(child.stdout).not.toContain("survived");
    }
  );

  it("never escalates turns without deliveries: external capacity polling and held jobs", async () => {
    vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
    const node = fixture();
    node.runtime.exchange.mockReturnValue({...idle, parked: {ordinary: false, serving: true}});
    node.runtime.exchange.mockReturnValueOnce({
      ...idle,
      gossip: gossip(...Array.from({length: 20}, (_, i) => ({messages: [i]}))),
    });
    // Every validation spends the budget, so each turn starts one held job.
    node.host.validate.mockImplementation(() => {
      node.advance(BUDGET_MS);
      return new Promise(() => undefined);
    });
    node.pump.request();
    for (let i = 0; i < 30; i++) {
      await macrotask();
      vi.advanceTimersByTime(25);
    }
    expect(node.host.validate).toHaveBeenCalledTimes(20);
    expect(node.runtime.exchange.mock.calls.length).toBeGreaterThan(20);
    expect(node.runtime.fail).not.toHaveBeenCalled();
    node.closed.resolve({reason: "requested"});
  });

  it("keeps turning whatever the host's error sink throws", async () => {
    const node = fixture();
    node.host.error.mockImplementation(() => {
      throw new Error("sink failed");
    });
    node.host.capacity.mockImplementationOnce(() => {
      throw new Error("capacity failed");
    });
    node.runtime.exchange.mockReturnValueOnce({...idle, more: true});
    node.pump.request();
    await macrotask();
    await macrotask();
    expect(node.runtime.exchange).toHaveBeenCalledTimes(2);
    expect(node.calls()[1][1]).toEqual(full);
  });

  it("measures each turn's burst through its continuations up to the next macrotask checkpoint", async () => {
    const node = fixture();
    node.host.peers.mockImplementation(() => {
      node.advance(1);
      void Promise.resolve().then(() => node.advance(2));
    });
    node.runtime.exchange.mockReturnValueOnce({...idle, more: true, peers: [peerEvent]});
    node.runtime.exchange.mockReturnValueOnce({...idle, peers: [peerEvent]});
    node.pump.request();
    for (let i = 0; i < 3; i++) await macrotask();
    const text = node.pump.metrics();
    const read = (suffix: string) => Number(new RegExp(`^${BURST_NAME}_${suffix} (\\S+)$`, "m").exec(text)?.[1]);
    // Two turns: each burst adds the continuation's 2 ms to the turn's own 1 ms, and neither includes the other.
    expect(read("count")).toBe(2);
    expect(read("sum")).toBeCloseTo(0.006, 9);
    expect(text).toContain(`${BURST_NAME}_bucket{le="0.0025"} 0\n`);
    expect(text).toContain(`${BURST_NAME}_bucket{le="0.005"} 2\n`);
    expect(text).toContain(`# TYPE ${BURST_NAME} histogram\n`);
  });
});

describe("binding pump delivery", () => {
  it("hands peers, then serving starts, then dependency checks, then gossip jobs to the host", async () => {
    const node = fixture();
    const order: string[] = [];
    node.host.peers.mockImplementation(() => void order.push("peers"));
    node.host.serve.mockImplementation(() => {
      order.push("serve");
      return Promise.resolve();
    });
    node.host.checkDependencies.mockImplementation((checks) => {
      order.push("checkDependencies");
      return checks.map(() => true);
    });
    node.host.validate.mockImplementation((job) => {
      order.push(`validate:${job.kind}`);
      return Promise.resolve(job.messages.map(() => "accept" as const));
    });
    node.runtime.exchange.mockReturnValueOnce({
      ...idle,
      checks: [check(9)],
      gossip: gossip({messages: [1], urgent: true}, {messages: [2]}),
      peers: [peerEvent],
      serving: [incoming() as NativeIncomingRequest],
    });
    node.pump.request();
    await macrotask();
    expect(order).toEqual(["peers", "serve", "checkDependencies", "validate:beacon_block", "validate:voluntary_exit"]);
    expect(node.host.peers).toHaveBeenCalledExactlyOnceWith([peerEvent]);
  });

  it("hands the host records that physically omit native handles and dispatch fields", async () => {
    const node = fixture();
    const start = incoming();
    node.runtime.exchange.mockReturnValueOnce({
      ...idle,
      checks: [check(9)],
      gossip: gossip({grouped: true, messages: [1, 2]}),
      serving: [start as NativeIncomingRequest],
    });
    node.pump.request();
    await macrotask();
    const job = node.host.validate.mock.calls[0][0];
    expect(Object.keys(job).sort()).toEqual(["grouped", "kind", "messages", "reported"]);
    expect(job).toMatchObject({grouped: true, kind: "beacon_attestation"});
    expect(Object.keys(job.messages[0]).sort()).toEqual([
      "attestationData",
      "connection",
      "data",
      "id",
      "peerId",
      "receivedAtUnixMs",
      "slot",
      "topic",
    ]);
    expect(job.messages[1].data).toEqual(new Uint8Array(4).fill(2));
    expect(node.host.checkDependencies.mock.calls[0][0]).toEqual([
      {peerId: "peer", root: new Uint8Array(32).fill(9), slot: 3n, topic: "topic"},
    ]);
    const request = node.host.serve.mock.calls[0][0];
    expect(Object.keys(request).sort()).toEqual(["closed", "connection", "data", "peerId", "protocol"]);
    expect("retainUntil" in request).toBe(false);
    await request.ready();
    await request.respond(new Uint8Array(1), null);
    await request.finish();
    await request.fail(3, new Uint8Array(1));
    await request.cancel();
    for (const method of ["ready", "respond", "finish", "fail", "cancel"] as const)
      expect(start[method]).toHaveBeenCalledOnce();
  });

  it("starts ordinary jobs until the budget, and one held job per turn, before claiming more", async () => {
    const node = fixture();
    node.host.validate.mockImplementation(() => {
      node.advance(5);
      return new Promise(() => undefined);
    });
    node.runtime.exchange
      .mockReturnValueOnce({...idle, gossip: gossip({messages: [1]}, {messages: [2]}, {messages: [3]})})
      .mockImplementationOnce(() => {
        // Settlement spent this turn's budget before delivery; the held job still starts.
        node.advance(BUDGET_MS);
        return {...idle, disabledWaiting: true};
      })
      .mockReturnValueOnce({...idle, gossip: gossip({messages: [4]})});
    node.pump.request();
    await macrotask();
    expect(node.host.validate).toHaveBeenCalledTimes(2);
    await macrotask();
    expect(node.host.validate).toHaveBeenCalledTimes(3);
    await macrotask();
    expect(node.host.validate).toHaveBeenCalledTimes(4);
    expect(node.calls().map(([, demand]) => demand.claimOrdinary)).toEqual([true, false, true]);
  });

  it("starts every urgent job in one turn past the budget while ordinary jobs yield at it", async () => {
    const node = fixture();
    const started: number[] = [];
    node.host.validate.mockImplementation((job) => {
      started.push(job.messages[0].data[0]);
      node.advance(5);
      return new Promise(() => undefined);
    });
    node.runtime.exchange
      .mockReturnValueOnce({
        ...idle,
        gossip: gossip(
          {messages: [4], urgent: true},
          {messages: [5], urgent: true},
          {messages: [6], urgent: true},
          {
            messages: [1],
          },
          {messages: [2]},
          {messages: [3]}
        ),
      })
      .mockReturnValueOnce({...idle, gossip: gossip({messages: [7], urgent: true})})
      .mockReturnValueOnce({...idle, disabledWaiting: true})
      .mockReturnValueOnce({...idle, gossip: gossip({messages: [8]})});
    node.pump.request();
    await macrotask();
    // All three blocks start although the first spends the budget; then one ordinary job starts.
    expect(started).toEqual([4, 5, 6, 1]);
    // Urgent work is delivered while ordinary jobs wait, and ordinary work is not claimed for the queue.
    await macrotask();
    expect(started).toEqual([4, 5, 6, 1, 7, 2]);
    await macrotask();
    expect(started).toEqual([4, 5, 6, 1, 7, 2, 3]);
    await macrotask();
    expect(started).toEqual([4, 5, 6, 1, 7, 2, 3, 8]);
    expect(node.calls().map(([, demand]) => demand.claimOrdinary)).toEqual([true, false, false, true]);
  });

  it("defers newly delivered ordinary jobs when earlier work in the turn spent its budget", async () => {
    const node = fixture();
    const started: number[] = [];
    node.host.validate.mockImplementation((job) => {
      started.push(job.messages[0].data[0]);
      return new Promise(() => undefined);
    });
    // Peers ran past the deadline before gossip delivery.
    node.host.peers.mockImplementation(() => node.advance(BUDGET_MS + 1));
    node.runtime.exchange.mockReturnValueOnce({
      ...idle,
      gossip: gossip({messages: [1]}, {messages: [2], urgent: true}),
      peers: [peerEvent],
    });
    node.pump.request();
    await macrotask();
    expect(started).toEqual([2]);
    // The next turn starts the held job whatever its budget, so held work progresses.
    node.runtime.exchange.mockImplementationOnce(() => {
      node.advance(BUDGET_MS);
      return idle;
    });
    await macrotask();
    expect(started).toEqual([2, 1]);
  });

  it.each([
    ["answers", (): readonly boolean[] => [true, false], [true, false], null],
    [
      "throws",
      () => {
        throw new Error("check failed");
      },
      [false, false],
      "check failed",
    ],
    ["miscounts", () => [true], [false, false], "NativeHostContract: checkDependencies"],
    ["returns no array", () => "yes" as unknown as boolean[], [false, false], "NativeHostContract: checkDependencies"],
    ["returns a sparse array", () => new Array<boolean>(2), [false, false], "NativeHostContract: checkDependencies"],
    [
      "returns a partially populated array",
      () => Object.assign([true], {length: 2}),
      [false, false],
      "NativeHostContract: checkDependencies",
    ],
    [
      "returns a non-boolean answer",
      () => [true, 1] as unknown as boolean[],
      [false, false],
      "NativeHostContract: checkDependencies",
    ],
  ])("classifies dependency checks in one call when the host %s", async (_, answer, classes, error) => {
    const node = fixture();
    node.host.checkDependencies.mockImplementationOnce(answer);
    node.runtime.exchange.mockReturnValueOnce({...idle, checks: [check(1), check(2)]});
    node.pump.request();
    await macrotask();
    await macrotask();
    expect(node.host.checkDependencies).toHaveBeenCalledOnce();
    expect(node.actions(1)).toEqual([
      {available: classes[0], handle: handle(1), type: "classify"},
      {available: classes[1], handle: handle(2), type: "classify"},
    ]);
    if (error === null) expect(node.host.error).not.toHaveBeenCalled();
    else expect(node.host.error).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({message: error}));
  });

  it.each([
    [
      "throws",
      () => {
        throw new Error("validator failed");
      },
      "validator failed",
    ],
    ["rejects", () => Promise.reject(new Error("validator failed")), "validator failed"],
    ["miscounts", () => Promise.resolve(["accept"] as const), "NativeHostContract: validate"],
    ["returns an unknown verdict", () => Promise.resolve(["accept", "maybe"]), "NativeHostContract: validate"],
    ["returns a sparse array", () => Promise.resolve(new Array(2)), "NativeHostContract: validate"],
    [
      "returns a partially populated array",
      () => Promise.resolve(Object.assign(["accept"], {length: 2})),
      "NativeHostContract: validate",
    ],
  ])("ignores every message of a job whose validation %s, and validates the others", async (_, validate, error) => {
    const node = fixture();
    node.host.validate.mockImplementationOnce(validate as () => Promise<readonly Verdict[]>);
    node.runtime.exchange.mockReturnValueOnce({
      ...idle,
      gossip: gossip({grouped: true, messages: [1, 2]}, {messages: [3]}),
    });
    node.pump.request();
    await macrotask();
    await macrotask();
    expect(node.actions(1)).toEqual([
      {handle: handle(1), type: "verdict", verdict: "ignore"},
      {handle: handle(2), type: "verdict", verdict: "ignore"},
      {handle: handle(3), type: "verdict", verdict: "accept"},
    ]);
    expect(node.host.error).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({message: error}));
    expect(node.terminal.failure).toBeNull();
  });

  it("a throwing peer handler ignores every job, cancels every unstarted start once and fails the network", async () => {
    const node = fixture();
    const held = incoming("held");
    const delivered = incoming("delivered");
    node.runtime.exchange
      .mockImplementationOnce(() => {
        node.advance(BUDGET_MS);
        return {...idle, serving: [held as NativeIncomingRequest]};
      })
      .mockReturnValueOnce({
        ...idle,
        checks: [check(3)],
        gossip: gossip({messages: [4], urgent: true}, {grouped: true, messages: [5, 6]}),
        peers: [peerEvent],
        serving: [delivered as NativeIncomingRequest],
      });
    const failure = new Error("peer handler failed");
    node.host.peers.mockImplementation(() => {
      throw failure;
    });
    node.pump.request();
    await macrotask();
    expect(held.retainUntil).not.toHaveBeenCalled();
    await macrotask();
    expect(node.terminal.failure).toBe(failure);
    expect(node.host.failed).toHaveBeenCalledExactlyOnceWith(failure);
    // The host closes the network once its cleanup finishes.
    expect(node.runtime.close).not.toHaveBeenCalled();
    expect(delivered.cancel).toHaveBeenCalledOnce();
    expect(held.cancel).toHaveBeenCalledOnce();
    await macrotask();
    // The failed network settles only, and reports what the host never took.
    expect(node.calls()[2]).toEqual([
      [
        {handle: handle(4), type: "verdict", verdict: "ignore"},
        {handle: handle(5), type: "verdict", verdict: "ignore"},
        {handle: handle(6), type: "verdict", verdict: "ignore"},
        {available: false, handle: handle(3), type: "classify"},
      ],
      control,
    ]);
    for (const callback of ["validate", "checkDependencies", "serve"] as const)
      expect(node.host[callback]).not.toHaveBeenCalled();
    node.pump.close();
    expect(held.cancel).toHaveBeenCalledOnce();
    expect(delivered.cancel).toHaveBeenCalledOnce();
  });

  it("fails the network for a serving start the binding could not hand over, after delivering the rest", async () => {
    const node = fixture();
    const failure = new Error("facade construction failed");
    node.runtime.exchange.mockReturnValueOnce({...idle, failure, more: true, peers: [peerEvent]});
    node.pump.request();
    await macrotask();
    expect(node.host.peers).toHaveBeenCalledOnce();
    expect(node.terminal.failure).toBe(failure);
    expect(node.host.failed).toHaveBeenCalledExactlyOnceWith(failure);
    expect(node.runtime.close).not.toHaveBeenCalled();
    await macrotask();
    expect(node.calls()[1][1]).toEqual(control);
  });

  it("keeps settling after a failure until the host closes, and reports only the first failure", async () => {
    const node = fixture();
    const first = new Error("first failure");
    node.runtime.exchange
      .mockReturnValueOnce({...idle, failure: first, more: true})
      .mockReturnValueOnce({...idle, failure: new Error("second failure"), more: true})
      .mockReturnValueOnce({...idle, more: true});
    node.pump.request();
    for (let i = 0; i < 4; i++) await macrotask();
    expect(node.calls().map(([, demand]) => demand)).toEqual([full, control, control, control]);
    expect(node.host.capacity).toHaveBeenCalledOnce();
    expect(node.host.failed).toHaveBeenCalledExactlyOnceWith(first);
    expect(node.terminal.failure).toBe(first);
    expect(node.runtime.close).not.toHaveBeenCalled();
  });

  it("closes native at once when the host's failure handler throws", async () => {
    const node = fixture();
    const thrown = new Error("cleanup failed");
    node.host.failed.mockImplementation(() => {
      throw thrown;
    });
    node.runtime.exchange.mockReturnValueOnce({...idle, failure: new Error("facade construction failed")});
    node.pump.request();
    await macrotask();
    expect(node.runtime.close).toHaveBeenCalledOnce();
    expect(node.host.error).toHaveBeenCalledExactlyOnceWith(thrown);
  });

  it("checks the budget between serving starts and keeps their order and capacity across turns", () => {
    const node = fixture();
    const starts = Array.from({length: 8}, (_, i) => incoming(`start-${i}`));
    const queue = starts.slice();
    node.runtime.exchange.mockImplementation((_actions, demand) => ({
      ...idle,
      serving: queue.splice(0, Math.min(demand.servingStarts, demand.capacity?.serving ?? 0)),
    }));
    node.host.serve.mockImplementation(() => {
      node.advance(BUDGET_MS);
      return new Promise(() => undefined);
    });
    for (let i = 0; i < starts.length; i++) {
      expect(node.pump.turn()).toBe(i === starts.length - 1 ? "idle" : "now");
      expect(node.host.serve).toHaveBeenCalledTimes(i + 1);
      expect(starts[i].retainUntil).toHaveBeenCalledOnce();
      const held = i === 0 ? 0 : starts.length - i;
      expect(node.calls()[i][1]).toMatchObject({capacity: {serving: 32 - held}, servingStarts: 8 - held});
    }
    expect(starts.every((start) => start.cancel.mock.calls.length === 0)).toBe(true);
  });

  it("holds serving starts once the budget is spent and starts them first next turn, counted once", async () => {
    const node = fixture();
    const starts = Array.from({length: 6}, (_, i) => incoming(`start-${i}`));
    const queue = starts.slice();
    let spend = true;
    node.runtime.exchange.mockImplementation((_actions, demand) => {
      if (spend) node.advance(BUDGET_MS);
      const count = Math.min(demand.servingStarts, demand.capacity?.serving ?? 0);
      return {...idle, serving: queue.splice(0, count) as NativeIncomingRequest[]};
    });
    node.host.capacity.mockReturnValue({ordinary: true, serving: 5});
    node.pump.request();
    await macrotask();
    // Settlement spent the budget: the delivered starts wait for the next turn, which follows at once.
    expect(queue).toHaveLength(1);
    expect(node.host.serve).not.toHaveBeenCalled();
    spend = false;
    node.host.capacity.mockReturnValue({ordinary: true, serving: 6});
    await macrotask();
    // Held starts count once against the next turn's capacity and allowance, and start before its new ones.
    expect(node.calls()[1][1]).toMatchObject({capacity: {serving: 1}, servingStarts: 3});
    expect(queue).toHaveLength(0);
    expect(node.host.serve).toHaveBeenCalledTimes(6);
    const retained = starts.map((start) => start.retainUntil.mock.invocationCallOrder[0]);
    expect(retained).toEqual([...retained].sort((a, b) => a - b));
  });

  it("never starts more than one turn's allowance, however many turns the budget ended", async () => {
    const node = fixture();
    const queue = Array.from({length: 40}, (_, i) => incoming(`start-${i}`));
    let spend = 4;
    node.runtime.exchange.mockImplementation((_actions, demand) => {
      if (spend > 0) {
        spend--;
        node.advance(BUDGET_MS);
      }
      const count = Math.min(demand.servingStarts, demand.capacity?.serving ?? 0);
      return {...idle, serving: queue.splice(0, count) as NativeIncomingRequest[]};
    });
    node.pump.request();
    // Four turns the budget ended: the first holds eight starts, which leave the others no allowance.
    for (let i = 0; i < 4; i++) await macrotask();
    expect(queue).toHaveLength(32);
    expect(node.calls()[3][1]).toMatchObject({capacity: {serving: 24}, servingStarts: 0});
    expect(node.host.serve).not.toHaveBeenCalled();
    await macrotask();
    expect(node.host.serve).toHaveBeenCalledTimes(8);
    expect(queue).toHaveLength(32);
    node.pump.request();
    await macrotask();
    expect(node.host.serve).toHaveBeenCalledTimes(16);
  });

  it("retains serving capacity until serve settles, registered before host code; a failure fails the stream once", async () => {
    const node = fixture();
    const [slow, thrown, rejected, ended] = ["slow", "thrown", "rejected", "ended"].map(incoming);
    ended.retainUntil.mockImplementation(() => {
      throw Object.assign(new Error("NetworkIncomingRetentionInvalid"), {code: "NetworkIncomingRetentionInvalid"});
    });
    const served = deferred<void>();
    const failure = new Error("serving failed");
    node.host.serve
      .mockImplementationOnce((request) => {
        expect(slow.retainUntil).toHaveBeenCalledOnce();
        expect(request.peerId).toBe("peer");
        return served.promise;
      })
      .mockImplementationOnce(() => {
        throw failure;
      })
      .mockImplementationOnce(() => Promise.reject(failure));
    node.runtime.exchange.mockReturnValueOnce({
      ...idle,
      serving: [slow, thrown, rejected, ended] as NativeIncomingRequest[],
    });
    node.pump.request();
    await macrotask();
    // A start whose stream ended while it was held is not served.
    expect(node.host.serve).toHaveBeenCalledTimes(3);
    const retirement = (start: Incoming) => {
      let settled = false;
      void start.retainUntil.mock.calls[0][0].then(() => {
        settled = true;
      });
      return () => settled;
    };
    const slowRetired = retirement(slow);
    const thrownRetired = retirement(thrown);
    const rejectedRetired = retirement(rejected);
    await macrotask();
    expect([slowRetired(), thrownRetired(), rejectedRetired()]).toEqual([false, true, true]);
    for (const start of [thrown, rejected]) {
      expect(start.fail).toHaveBeenCalledOnce();
      expect(start.fail.mock.calls[0][0]).toBe(2);
      expect(new TextDecoder().decode(start.fail.mock.calls[0][1])).toBe("Local serving failure");
    }
    expect(node.host.error).toHaveBeenCalledTimes(2);
    expect(slow.fail).not.toHaveBeenCalled();
    const exchanges = node.runtime.exchange.mock.calls.length;
    served.resolve();
    await macrotask();
    expect(slowRetired()).toBe(true);
    // Released capacity drains again.
    await macrotask();
    expect(node.runtime.exchange.mock.calls.length).toBeGreaterThan(exchanges);
    for (const start of [slow, thrown, rejected, ended]) expect(start.cancel).not.toHaveBeenCalled();
  });

  it.each([
    ["capacity read", 0, [], 0, 0, 0, 0],
    ["exchange's settlement", 0, [1, 2, 3], false, 0, 0, 2],
    ["peer handler", 1, [1, 2, 3], false, 0, 0, 2],
    ["first serve", 1, [1, 2, 3], false, 1, 0, 1],
    ["dependency check", 1, [1, 2, 3], true, 2, 0, 0],
    ["urgent validation", 1, [2, 3], true, 2, 1, 0],
    ["ordinary validation", 1, [3], true, 2, 2, 0],
  ] as const)("a close from the host's %s ends the delivery and retires the rest once", async (closer, peers, ignored, available, served, validated, cancelled) => {
    const node = fixture();
    const starts = [incoming("first"), incoming("second")];
    const close = (name: string) => {
      if (name === closer) node.pump.close();
    };
    node.host.capacity.mockImplementation(() => {
      close("capacity read");
      return {ordinary: true, serving: 32};
    });
    node.runtime.exchange.mockImplementationOnce((_actions, demand) => {
      close("exchange's settlement");
      if (demand.messages === 0) return idle;
      return {
        ...idle,
        checks: [check(7)],
        gossip: gossip({messages: [1], urgent: true}, {messages: [2]}, {messages: [3]}),
        peers: [peerEvent],
        serving: starts as NativeIncomingRequest[],
      };
    });
    node.host.peers.mockImplementation(() => close("peer handler"));
    node.host.serve.mockImplementation(() => {
      close("first serve");
      return Promise.resolve();
    });
    node.host.checkDependencies.mockImplementation((checks) => {
      close("dependency check");
      return checks.map(() => true);
    });
    node.host.validate.mockImplementation((job) => {
      close(job.messages[0].data[0] === 1 ? "urgent validation" : "ordinary validation");
      return new Promise(() => undefined);
    });
    node.pump.request();
    await macrotask();
    await macrotask();
    expect(node.host.peers).toHaveBeenCalledTimes(peers);
    expect(node.host.serve).toHaveBeenCalledTimes(served);
    expect(node.host.validate).toHaveBeenCalledTimes(validated);
    expect(starts.map(({cancel}) => cancel.mock.calls.length).reduce((a, b) => a + b)).toBe(cancelled);
    if (served === 1) expect(starts[1].cancel).toHaveBeenCalledOnce();
    // The next exchange settles only, retiring each undelivered message and check once.
    const retired: NativeAction[] = ignored.map((index) => ({
      handle: handle(index),
      type: "verdict",
      verdict: "ignore",
    }));
    if (available !== 0) retired.push({available, handle: handle(7), type: "classify"});
    if (retired.length === 0) expect(node.calls()).toEqual([[[], control]]);
    else {
      expect(node.calls()[1][1]).toEqual(control);
      expect(node.actions(1)).toHaveLength(retired.length);
      expect(node.actions(1)).toEqual(expect.arrayContaining(retired));
    }
  });

  it("close cancels held serving starts once and ignores held jobs", async () => {
    const node = fixture();
    const held = incoming("held");
    node.runtime.exchange.mockImplementationOnce(() => {
      node.advance(BUDGET_MS);
      return {...idle, gossip: gossip({messages: [1]}), serving: [held as NativeIncomingRequest]};
    });
    node.pump.request();
    await macrotask();
    node.pump.close();
    node.pump.close();
    expect(held.cancel).toHaveBeenCalledOnce();
    await macrotask();
    expect(node.calls()[1]).toEqual([[{handle: handle(1), type: "verdict", verdict: "ignore"}], control]);
    expect(node.host.validate).not.toHaveBeenCalled();
    expect(node.host.serve).not.toHaveBeenCalled();
    node.closed.resolve({reason: "requested"});
    await macrotask();
    expect(held.cancel).toHaveBeenCalledOnce();
  });
});

describe("binding pump acknowledgements", () => {
  it("resolves a job's report only when every message has an owner disposition", async () => {
    const node = fixture();
    node.runtime.exchange.mockReturnValueOnce({...idle, gossip: gossip({grouped: true, messages: [1, 2, 3]})});
    node.pump.request();
    await macrotask();
    const job = node.host.validate.mock.calls[0][0];
    let reported = false;
    void job.reported.then(() => {
      reported = true;
    });
    // Acknowledgements are control work: they arrive whatever the demand, and hand the host nothing else.
    node.host.capacity.mockReturnValue(null);
    node.runtime.exchange.mockReturnValueOnce({...idle, acknowledged: [handle(1), handle(3)], more: true});
    await macrotask();
    await macrotask();
    expect(reported).toBe(false);
    node.runtime.exchange.mockReturnValueOnce({...idle, acknowledged: [handle(2)]});
    node.pump.request();
    await macrotask();
    await macrotask();
    expect(reported).toBe(true);
    expect(node.host.peers).not.toHaveBeenCalled();
  });

  it("matches acknowledgements by generation, so a reused cell's stale handle resolves nothing", async () => {
    const node = fixture();
    node.runtime.exchange.mockReturnValueOnce({...idle, gossip: gossip({generation: 1n, messages: [0]})});
    node.pump.request();
    await macrotask();
    node.runtime.exchange.mockReturnValueOnce({
      ...idle,
      acknowledged: [handle(0, 1n)],
      gossip: gossip({generation: 2n, messages: [0]}),
    });
    node.pump.request();
    await macrotask();
    const [first, second] = node.host.validate.mock.calls.map(([job]) => job);
    await expect(first.reported).resolves.toBeUndefined();
    let reported = false;
    void second.reported.then(() => {
      reported = true;
    });
    node.runtime.exchange.mockReturnValueOnce({...idle, acknowledged: [handle(0, 1n), handle(9, 2n)]});
    node.pump.request();
    await macrotask();
    await macrotask();
    expect(reported).toBe(false);
    node.runtime.exchange.mockReturnValueOnce({...idle, acknowledged: [handle(0, 2n)]});
    node.pump.request();
    await macrotask();
    await expect(second.reported).resolves.toBeUndefined();
  });

  it("rejects every outstanding report when native closes, and keeps resolved ones", async () => {
    const node = fixture();
    node.runtime.exchange.mockReturnValueOnce({
      ...idle,
      gossip: gossip({messages: [1]}, {grouped: true, messages: [2, 3]}),
    });
    node.pump.request();
    await macrotask();
    node.runtime.exchange.mockReturnValueOnce({...idle, acknowledged: [handle(1), handle(2)]});
    node.pump.request();
    await macrotask();
    const [done, open] = node.host.validate.mock.calls.map(([job]) => job);
    node.closed.resolve({reason: "requested"});
    await expect(done.reported).resolves.toBeUndefined();
    await expect(open.reported).rejects.toMatchObject({code: "NetworkClosed"});
    node.pump.request();
    await macrotask();
    expect(node.runtime.exchange).toHaveBeenCalledTimes(2);
  });

  it("settles a report's derivatives at native close while the pump lives, though nothing retains the report", async () => {
    const node = fixture();
    const outcome = (promise: Promise<unknown>) =>
      promise.then(
        () => "resolved",
        (error: {code?: unknown}) => error.code
      );
    let derived: Promise<unknown>[] = [];
    let source: WeakRef<Promise<void>> | undefined;
    node.host.validate.mockImplementation((job) => {
      derived = [outcome(job.reported), outcome(Promise.all([macrotask(), job.reported]))];
      source = new WeakRef(job.reported);
      return new Promise(() => undefined);
    });
    node.runtime.exchange.mockReturnValueOnce({...idle, gossip: gossip({messages: [1]})});
    node.pump.request();
    await macrotask();
    // Only the pump now holds the report.
    node.host.validate.mockClear();
    for (let i = 0; i < 3; i++) {
      global.gc?.();
      await macrotask();
    }
    expect(source?.deref()).toBeInstanceOf(Promise);
    node.closed.resolve({reason: "requested"});
    expect(await Promise.all(derived)).toEqual(["NetworkClosed", "NetworkClosed"]);
  });
});

describe("binding pump close results", () => {
  it("reports a requested close, and a failed one with the owner's terminal error", async () => {
    const node = fixture();
    const owner = Object.assign(new Error("NetworkWakeFailed"), {code: "NetworkWakeFailed"});
    expect(await closeResult(Promise.resolve({reason: "requested"}), node.terminal)).toEqual({reason: "requested"});
    expect(await closeResult(Promise.resolve({error: owner, reason: "failed"}), node.terminal)).toEqual({
      error: owner,
      reason: "failed",
    });
  });

  it("reports an owner failure that follows a requested close", async () => {
    const node = fixture();
    const result = closeResult(node.runtime.closed, node.terminal);
    node.pump.close();
    const owner = new Error("owner failed while stopping");
    node.closed.resolve({error: owner, reason: "failed"});
    expect(await result).toEqual({error: owner, reason: "failed"});
  });

  it("reports a delivery failure first, once native settles the close the host then requests", async () => {
    const node = fixture();
    const result = closeResult(node.runtime.closed, node.terminal);
    let settled = false;
    void result.then(() => {
      settled = true;
    });
    const failure = new Error("peer handler failed");
    node.host.peers.mockImplementation(() => {
      throw failure;
    });
    node.runtime.exchange.mockReturnValueOnce({...idle, peers: [peerEvent]});
    node.pump.request();
    await macrotask();
    expect(node.host.failed).toHaveBeenCalledExactlyOnceWith(failure);
    await macrotask();
    expect(settled).toBe(false);
    node.closed.resolve({reason: "requested"});
    expect(await result).toEqual({error: failure, reason: "failed"});
  });

  it.each([
    "held",
    "unadopted",
  ] as const)("keeps a delivery failure first when cancelling a %s serving start records a later owner failure", async (kind) => {
    const node = fixture();
    const result = closeResult(node.runtime.closed, node.terminal);
    const start = incoming(kind);
    // A real cancellation reaches native, whose wake can record a terminal failure.
    start.cancel.mockImplementation(() => {
      node.runtime.state = "failed";
      return Promise.resolve();
    });
    const failure = new Error("peer handler failed");
    node.host.peers.mockImplementation(() => {
      throw failure;
    });
    if (kind === "held")
      node.runtime.exchange
        .mockImplementationOnce(() => {
          node.advance(BUDGET_MS);
          return {...idle, serving: [start as NativeIncomingRequest]};
        })
        .mockReturnValueOnce({...idle, peers: [peerEvent]});
    else
      node.runtime.exchange.mockReturnValueOnce({
        ...idle,
        peers: [peerEvent],
        serving: [start as NativeIncomingRequest],
      });
    node.pump.request();
    await macrotask();
    if (kind === "held") await macrotask();
    expect(start.cancel).toHaveBeenCalledOnce();
    expect(node.runtime.state).toBe("failed");
    expect(node.host.failed).toHaveBeenCalledExactlyOnceWith(failure);
    expect(node.host.error).not.toHaveBeenCalled();
    node.closed.resolve({error: new Error("NetworkWakeFailed"), reason: "failed"});
    expect(await result).toEqual({error: failure, reason: "failed"});
  });

  it("leaves the close result to an owner that failed first, and reports a later delivery failure", async () => {
    const node = fixture();
    const result = closeResult(node.runtime.closed, node.terminal);
    node.runtime.state = "failed";
    const failure = new Error("peer handler failed");
    node.host.peers.mockImplementation(() => {
      throw failure;
    });
    node.runtime.exchange.mockReturnValueOnce({...idle, peers: [peerEvent]});
    node.pump.request();
    await macrotask();
    expect(node.host.failed).not.toHaveBeenCalled();
    expect(node.host.error).toHaveBeenCalledExactlyOnceWith(failure);
    expect(node.terminal.failure).toBeNull();
    const owner = new Error("owner failed");
    node.closed.resolve({error: owner, reason: "failed"});
    expect(await result).toEqual({error: owner, reason: "failed"});
  });
});

it("stops log delivery with a final drain when native closes", async () => {
  vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
  const node = fixture();
  node.runtime.drainLogs.mockReturnValue({...noLogs, more: true});
  node.closed.resolve({reason: "requested"});
  await macrotask();
  expect(node.runtime.drainLogs).toHaveBeenCalledTimes(4);
  expect(vi.getTimerCount()).toBe(0);
  vi.advanceTimersByTime(2500);
  expect(node.runtime.drainLogs).toHaveBeenCalledTimes(4);
});
