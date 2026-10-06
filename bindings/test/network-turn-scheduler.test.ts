import {afterEach, expect, it, vi} from "vitest";
import {TurnScheduler} from "../src/network-turn-scheduler.js";
import {immediates} from "./utils/network-turn-scheduler.js";

afterEach(() => {
  vi.clearAllTimers();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

it.each(["now", "later", "idle"] as const)("schedules the pump's %s continuation", (next) => {
  vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
  const timers = vi.spyOn(globalThis, "setTimeout");
  const queued = immediates();
  const pump = {turn: vi.fn(() => next)};
  const scheduler = new TurnScheduler(pump);
  scheduler.schedule();
  scheduler.schedule();
  expect(queued).toHaveLength(1);
  queued.shift()?.();
  expect(pump.turn).toHaveBeenCalledOnce();
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
