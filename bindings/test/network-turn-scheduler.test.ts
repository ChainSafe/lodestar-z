import {afterEach, expect, it, vi} from "vitest";
import type {NativeAction, NativeExchange, NativeExchangeDemand} from "../src/network-runtime.js";
import {TurnScheduler, CONTROL as control} from "../src/network-turn-scheduler.js";
import {Escalated, immediates, runUntilEscalated} from "./utils/network-turn-scheduler.js";

const idle: NativeExchange = {
  acknowledged: [],
  checks: [],
  closed: null,
  completions: [],
  disabledWaiting: false,
  gossip: null,
  more: false,
  parked: {ordinary: false, serving: false},
  peers: [],
  serving: [],
};

afterEach(() => {
  vi.clearAllTimers();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

it("without a live pump, turns drain control while native reports more, and escalate a failed drain", () => {
  vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
  const queued = immediates();
  const failure = new Error("exchange failed");
  const results: (NativeExchange | Error)[] = [{...idle, more: true}, idle, failure];
  const route = {
    exchange: vi.fn((_actions: readonly NativeAction[], _demand: NativeExchangeDemand): NativeExchange => {
      const result = results.shift() ?? idle;
      if (result instanceof Error) throw result;
      return result;
    }),
    fail: vi.fn((site: string, _reason: string): never => {
      throw new Escalated(site);
    }),
  };
  const scheduler = new TurnScheduler(route);
  scheduler.schedule();
  scheduler.schedule();
  expect(runUntilEscalated(queued, 5)).toBe(false);
  expect(route.exchange.mock.calls).toEqual([
    [[], control],
    [[], control],
  ]);
  // Only a notification brings the next drain, a refusal escalates immediately.
  scheduler.schedule();
  expect(runUntilEscalated(queued, 20)).toBe(true);
  expect(route.exchange).toHaveBeenCalledTimes(3);
  expect(route.fail).toHaveBeenCalledExactlyOnceWith("generated_batch", "exchange failed");
});

it.each(["now", "later", "idle"] as const)("schedules the pump's %s continuation", (next) => {
  vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
  const timers = vi.spyOn(globalThis, "setTimeout");
  const queued = immediates();
  const route = {
    exchange: vi.fn(() => idle),
    fail: vi.fn((): never => {
      throw new Escalated();
    }),
  };
  const scheduler = new TurnScheduler(route);
  const pump = {turn: vi.fn(() => next)};
  scheduler.bind(pump);
  scheduler.schedule();
  queued.shift()?.();
  expect(pump.turn).toHaveBeenCalledOnce();
  expect(route.exchange).not.toHaveBeenCalled();
  expect(queued.length).toBe(next === "now" ? 1 : 0);
  expect(timers).toHaveBeenCalledTimes(next === "later" ? 1 : 0);
  if (next === "later") {
    expect(timers.mock.results[0].value.hasRef()).toBe(false);
    vi.advanceTimersByTime(25);
    expect(queued).toHaveLength(1);
  }
  scheduler.stop();
  queued.shift()?.();
  expect(pump.turn).toHaveBeenCalledOnce();
});
