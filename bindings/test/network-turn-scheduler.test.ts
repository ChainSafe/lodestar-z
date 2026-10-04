import {afterEach, expect, it, vi} from "vitest";
import type {NativeAction, NativeExchange, NativeExchangeDemand} from "../src/network-runtime.js";
import {TurnScheduler, CONTROL as control} from "../src/network-turn-scheduler.js";

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

import {Escalated, immediates, runUntilEscalated} from "./utils/network-turn-scheduler.js";

afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

it("without a live pump, turns drain control while native reports more, and escalate a third failed drain", () => {
  vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
  const queued = immediates();
  const failure = new Error("exchange failed");
  const results: (NativeExchange | Error)[] = [{...idle, more: true}, idle, failure, failure, failure];
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
  // Only a notification brings the next drain, and failed ones retry on the timer.
  scheduler.schedule();
  expect(runUntilEscalated(queued, 20)).toBe(true);
  expect(route.exchange).toHaveBeenCalledTimes(5);
  expect(route.fail).toHaveBeenCalledExactlyOnceWith("failed_turns", "exchange failed");
});
