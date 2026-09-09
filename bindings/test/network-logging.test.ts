import {expect, test} from "vitest";
import {type NativeLogRecord, type NativeNetworkRuntime, createNativeNetworkRuntime} from "../src/network.js";
import {networkConfig} from "./utils/network.js";
import {BLOCKS, incomingPair, takeIncoming} from "./utils/network-incoming.js";

function drain(runtime: Pick<NativeNetworkRuntime, "drainLogs">): NativeLogRecord[] {
  const records: NativeLogRecord[] = [];
  for (let i = 0; i < 4; i++) {
    const batch = runtime.drainLogs(32);
    records.push(...batch.records);
    if (!batch.more) return records;
  }
  throw Error("Unexpected log volume");
}

test("native std.log captures lifecycle, timestamps and isolated sessions through close", async () => {
  const left = createNativeNetworkRuntime(networkConfig(), () => undefined);
  const right = createNativeNetworkRuntime(networkConfig(), () => undefined);
  try {
    const identities = await Promise.all([left.ready, right.ready]);
    await Promise.all([left.close(), right.close()]);
    for (const [runtime, identity] of [
      [left, identities[0]],
      [right, identities[1]],
    ] as const) {
      const {default: addon} = await import("../src/bindings.js");
      if (typeof addon.networkTestFail === "function") {
        addon.networkTestFail("drain_copy");
        expect(() => runtime.drainLogs()).toThrow("InjectedNetworkFailure");
      }
      const records = drain(runtime);
      expect(records.some((r) => r.message.startsWith("owner_initializing "))).toBe(true);
      expect(records.some((r) => r.message.startsWith("owner_ready "))).toBe(true);
      expect(records.some((r) => r.message.startsWith("owner_stopped reason=requested "))).toBe(true);
      let sequence = 0n;
      for (const record of records) {
        expect(record.session).toBe(identity.session);
        expect(record.sequence).toBeGreaterThan(sequence);
        expect(record.timestampMs).toBeGreaterThan(BigInt(Date.now() - 20000));
        expect(record.monotonicMs).toBeGreaterThan(0n);
        expect(Buffer.byteLength(record.message)).toBeLessThanOrEqual(768);
        expect([...record.message].every((char) => char.charCodeAt(0) >= 32 && char.charCodeAt(0) <= 126)).toBe(true);
        sequence = record.sequence;
      }
      expect(runtime.drainLogs().records).toEqual([]);
      expect(runtime.getMetrics()).toContain("lodestar_native_logs_queued 0\n");
    }
    expect(identities[0].session).not.toBe(identities[1].session);
  } finally {
    await Promise.all([left.close(), right.close()]);
  }
}, 20000);

test("ReleaseSafe debug logs correlate real requests without draining request data", async () => {
  const pair = await incomingPair();
  try {
    pair.left.setLogLevel("debug");
    pair.right.setLogLevel("debug");
    drain(pair.left);
    drain(pair.right);
    const request = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32).fill(7));
    const pending = request.next();
    void pending.catch(() => undefined);
    const incoming = await takeIncoming(pair.right);
    await incoming.finish();
    expect(await pending).toEqual({done: true, value: undefined});
    for (const runtime of [pair.left, pair.right]) {
      const records = drain(runtime).filter((r) => r.message.includes("method=blocks_by_root_v2"));
      const started = records.find((r) => r.message.startsWith("request_started "));
      const completed = records.find((r) => r.message.startsWith("request_completed "));
      expect(started).toBeDefined();
      expect(completed).toBeDefined();
      expect(started?.level).toBe("debug");
      expect(started?.message.match(/request=(\d+:\d+)/)?.[1]).toBe(completed?.message.match(/request=(\d+:\d+)/)?.[1]);
      expect(started?.message.match(/connection=(\d+:\d+)/)?.[1]).toBe(
        completed?.message.match(/connection=(\d+:\d+)/)?.[1]
      );
    }
    const failed = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32));
    const failedNext = failed.next();
    const rejected = expect(failedNext).rejects.toMatchObject({peerStatus: 2, reason: "peer_error"});
    const rejectedIncoming = await takeIncoming(pair.right);
    await rejectedIncoming.fail(2, new TextEncoder().encode("untrusted response text\nsecret"));
    await rejected;
    const failures = drain(pair.left).filter((r) => r.scope === "network_reqresp_errors");
    expect(failures.some((r) => r.message.startsWith("request_failed "))).toBe(true);
    expect(failures.some((r) => r.message.includes("reason=peer_error detail=none peer_code=2"))).toBe(true);
    expect(failures.every((r) => !r.message.includes("untrusted response text") && !r.message.includes("secret"))).toBe(
      true
    );
  } finally {
    await Promise.all([pair.left.close(), pair.right.close()]);
  }
}, 20000);

test("native logging rejects malformed controls and honors off", async () => {
  const runtime = createNativeNetworkRuntime(networkConfig(), () => undefined);
  try {
    await runtime.ready;
    for (const level of ["debug-extra", "info-extra", "error-extra", "", "trace", "DEBUG", "debug\0", null, 0]) {
      expect(() => Reflect.apply(runtime.setLogLevel, runtime, [level])).toThrow("InvalidNetworkLogLevel");
    }
    for (const limit of [0, -1, 33, 1.5, NaN, Infinity, "1", null]) {
      expect(() => Reflect.apply(runtime.drainLogs, runtime, [limit])).toThrow("InvalidDrainLimit");
    }
    runtime.setLogLevel("off");
    drain(runtime);
    await runtime.close();
    expect(drain(runtime)).toEqual([]);
  } finally {
    await runtime.close();
  }
});
