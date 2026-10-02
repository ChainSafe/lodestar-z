import {afterEach, describe, expect, it, vi} from "vitest";
import type {NativeLogLoss, NativeLogRecord} from "../src/network.js";
import {LOG_DRAIN_ERRORS_NAME, LOG_ERRORS_NAME, LOG_MS, LOG_RECORDS, LogDelivery} from "../src/network-log-delivery.js";
import type {NativeLogBatch} from "../src/network-runtime.js";

const noLogs: NativeLogBatch = {dropped: 0n, more: false, records: [], suppressed: 0n, truncated: 0n};

function fixture() {
  const runtime = {drainLogs: vi.fn((_max: number): NativeLogBatch => noLogs)};
  const host = {
    error: vi.fn((_error: unknown): void => undefined),
    logs: vi.fn((_records: readonly NativeLogRecord[], _lost: NativeLogLoss | null): void => undefined),
  };
  const logs = new LogDelivery(runtime, host, host.error);
  logs.start();
  return {host, logs, runtime};
}

afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

function logRecord(sequence: number): NativeLogRecord {
  return {
    level: "info",
    message: `record ${sequence}`,
    monotonicMs: 1n,
    scope: "network_runtime",
    sequence: BigInt(sequence),
    timestampMs: 1n,
    truncated: false,
  };
}

describe("native log delivery", () => {
  it("delivers up to 32 native records every 250 ms, one batch each time", () => {
    vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
    const node = fixture();
    const records = [logRecord(1), logRecord(2)];
    node.runtime.drainLogs.mockReturnValue({...noLogs, more: true, records});
    vi.advanceTimersByTime(LOG_MS - 1);
    expect(node.runtime.drainLogs).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(node.runtime.drainLogs).toHaveBeenCalledExactlyOnceWith(LOG_RECORDS);
    expect(node.host.logs).toHaveBeenCalledExactlyOnceWith(records, null);
    vi.advanceTimersByTime(LOG_MS);
    expect(node.host.logs).toHaveBeenCalledTimes(2);
    // An empty batch is not delivered.
    node.runtime.drainLogs.mockReturnValue(noLogs);
    vi.advanceTimersByTime(LOG_MS);
    expect(node.host.logs).toHaveBeenCalledTimes(2);
  });

  it("counts undelivered records separately from failed drains", () => {
    vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
    const node = fixture();
    node.runtime.drainLogs.mockReturnValue({...noLogs, records: [logRecord(1), logRecord(2)]});
    node.host.logs.mockImplementation(() => {
      throw new Error("logger failed");
    });
    vi.advanceTimersByTime(LOG_MS);
    const failure = new Error("drain failed");
    node.runtime.drainLogs.mockImplementationOnce(() => {
      throw failure;
    });
    vi.advanceTimersByTime(LOG_MS);
    vi.advanceTimersByTime(LOG_MS);
    expect(node.host.logs).toHaveBeenCalledTimes(2);
    expect(node.logs.metrics()).toContain(`${LOG_ERRORS_NAME} 4\n`);
    expect(node.host.error).toHaveBeenCalledExactlyOnceWith(failure);
    expect(node.logs.metrics()).toContain(`${LOG_DRAIN_ERRORS_NAME} 1\n`);
  });

  it("drains at most four final batches, then stops", () => {
    vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
    const node = fixture();
    node.runtime.drainLogs.mockReturnValue({...noLogs, more: true, records: [logRecord(1)]});
    node.logs.stop();
    expect(node.host.logs).toHaveBeenCalledTimes(4);
    expect(vi.getTimerCount()).toBe(0);
    vi.advanceTimersByTime(10 * LOG_MS);
    expect(node.host.logs).toHaveBeenCalledTimes(4);
  });

  it("reports the records native lost since the last report once dropped or truncated ones grew, at most every 30 s despite wall clock corrections", () => {
    vi.useFakeTimers({toFake: ["setTimeout", "clearTimeout"]});
    let now = 1_000_000;
    let wall = now;
    vi.spyOn(performance, "now").mockImplementation(() => now);
    vi.spyOn(Date, "now").mockImplementation(() => wall);
    const node = fixture();
    const deliver = (stats: {dropped: bigint; suppressed: bigint; truncated: bigint}) => {
      node.runtime.drainLogs.mockReturnValueOnce({...noLogs, ...stats});
      vi.advanceTimersByTime(LOG_MS);
      return node.host.logs.mock.calls.at(-1)?.[1];
    };
    expect(deliver({dropped: 3n, suppressed: 1n, truncated: 0n})).toEqual({dropped: 3n, suppressed: 1n, truncated: 0n});
    const reports = node.host.logs.mock.calls.length;
    now += 29_000;
    wall += 60_000;
    deliver({dropped: 5n, suppressed: 1n, truncated: 1n});
    expect(node.host.logs).toHaveBeenCalledTimes(reports);
    now += 1_000;
    wall -= 120_000;
    expect(deliver({dropped: 5n, suppressed: 4n, truncated: 1n})).toEqual({dropped: 2n, suppressed: 3n, truncated: 1n});
    // Suppression alone is not reported.
    now += 30_000;
    deliver({dropped: 5n, suppressed: 9n, truncated: 1n});
    expect(node.host.logs).toHaveBeenCalledTimes(reports + 1);
  });
});
