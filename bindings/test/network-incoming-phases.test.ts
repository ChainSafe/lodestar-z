import {expect, test} from "vitest";
import bindings from "../src/bindings.js";
import type {NativeIncomingRequest} from "../src/network.js";
import {BLOCKS, incomingPair, takeIncoming} from "./utils/network-incoming.js";

interface PhaseSnapshot {
  preparing: boolean;
  heavyFreed: boolean;
  currentRefs: number;
  nextRefs: number;
  responseBytes: number;
  deferred: boolean;
  copiedFirstByte: number;
  rollback: boolean;
  rollbackNextRefs: number;
  rollbackReserved: number;
  bufferReleased: boolean;
  deferredRetired: boolean;
  pendingPublished: boolean;
  terminalBefore: boolean;
  terminalAccepted: boolean;
  nativeFinishing: boolean;
  nativeErrorWriting: boolean;
  nativeTerminal: boolean;
  chunks: number;
  stepObserved: boolean;
  stepFinishing: boolean;
  stepWriting: boolean;
  stepCloseAfterWrite: boolean;
  stepErrorStatus: number;
  stepNativeState: number;
  stepTerminal: boolean;
  stepChunks: number;
}
const hooks = bindings as unknown as {
  networkTestScenario(value: string): void;
  networkTestFail(value: string): void;
  networkTestIncomingPhase(): PhaseSnapshot;
  networkTestIncomingRelease(): void;
  networkTestIncoming(): {nativeInbound: number};
};
const instrumented = test.skipIf(process.env.LODESTAR_Z_NETWORK_TEST_FAILURES !== "1");

instrumented.each([
  ["refs", false],
  ["refs", true],
  ["buffer", false],
  ["buffer", true],
  ["deferred", false],
  ["deferred", true],
] as const)(
  "physical close during response preparation %s, fault=%s",
  async (phase, fault) => {
    const pair = await incomingPair(() => hooks.networkTestScenario(`incoming_prepare_${phase}`));
    try {
      const pending = pair.left
        .request(pair.remote.peerId, BLOCKS, new Uint8Array(32))
        .next()
        .catch(() => undefined);
      const incoming = await takeIncoming(pair.right);
      if (fault) hooks.networkTestFail(phase === "refs" ? "incoming_result_4" : "operation_copy");
      await expect(
        incoming.respond(new Uint8Array(4000).fill(71), pair.rightConfig.requestForks[0])
      ).rejects.toMatchObject({
        code: fault ? "InjectedNetworkFailure" : "NetworkClosed",
      });
      console.log(JSON.stringify({phase, snapshot: hooks.networkTestIncomingPhase()}));
      expect(hooks.networkTestIncomingPhase()).toMatchObject({
        bufferReleased: phase !== "refs" || !fault,
        copiedFirstByte: phase === "deferred" ? 71 : 0,
        currentRefs: 9,
        deferred: phase === "deferred",
        deferredRetired: phase === "deferred" || !fault,
        heavyFreed: true,
        nextRefs: phase === "refs" ? 3 : 9,
        pendingPublished: false,
        preparing: true,
        responseBytes: phase === "refs" ? 0 : 4000,
        rollback: true,
        rollbackNextRefs: 0,
        rollbackReserved: 0,
      });
      expect(await incoming.closed).toEqual({chunks: 0, reason: "closed"});
      expect(pair.right.diagnostics()).toMatchObject({
        copyingPins: 0,
        incoming: {
          closedPromises: 0,
          occupied: 0,
          pendingResponses: 0,
          requestBytes: 0,
          reservedBytes: 0,
          responseBytes: 0,
        },
        liveNativeRequestedBytes: 0,
        preparingPins: 0,
      });
      await checkReplacement(incoming, pair.right.diagnostics().session);
      await pending;
    } finally {
      await Promise.all([pair.left.close(), pair.right.close()]);
    }
  },
  20000
);

instrumented.each([
  ["finish", "before"],
  ["fail", "before"],
  ["finish", "after"],
  ["fail", "after"],
] as const)(
  "cancel admitted for %s at proved %s submission phase",
  async (action, phase) => {
    const pair = await incomingPair(() => hooks.networkTestScenario(`incoming_terminal_${phase}`));
    try {
      const stream = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(64));
      const first = stream.next();
      void first.catch(() => undefined);
      const incoming = await takeIncoming(pair.right);
      await incoming.respond(new Uint8Array(4000), pair.rightConfig.requestForks[0]);
      expect((await first).done).toBe(false);
      const pending = stream.next().catch(() => undefined);
      const closed =
        action === "finish" ? incoming.finish() : incoming.fail(139, new TextEncoder().encode("unfinished"));
      expect(closed).toBe(incoming.closed);
      await expect
        .poll(
          () => hooks.networkTestIncomingPhase().terminalBefore || hooks.networkTestIncomingPhase().terminalAccepted
        )
        .toBe(true);
      console.log(JSON.stringify({action, phase, snapshot: hooks.networkTestIncomingPhase()}));
      expect(hooks.networkTestIncomingPhase()).toMatchObject({
        chunks: 1,
        nativeErrorWriting: phase === "after" && action === "fail",
        nativeFinishing: phase === "after" && action === "finish",
        nativeTerminal: false,
        terminalAccepted: phase === "after",
        terminalBefore: phase === "before",
      });
      expect(incoming.cancel()).toBe(closed);
      expect(incoming.cancel()).toBe(closed);
      expect(incoming.finish()).toBe(closed);
      expect(incoming.fail(1, new Uint8Array())).toBe(closed);
      const outcome = await closed;
      const completed = hooks.networkTestIncomingPhase();
      console.log(JSON.stringify({action, outcome, phase, snapshot: completed}));
      expect(completed).toMatchObject({
        stepChunks: phase === "after" ? 1 : 0,
        stepCloseAfterWrite: phase === "after" && action === "fail",
        stepErrorStatus: phase === "after" && action === "fail" ? 139 : 0,
        stepObserved: phase === "after",
        stepTerminal: phase === "after" && action === "finish",
      });
      expect(completed.stepWriting || completed.stepFinishing).toBe(phase === "after" && action === "fail");
      expect(outcome).toEqual(
        phase === "after" && action === "finish"
          ? {chunks: 1, reason: "served"}
          : {chunks: 1, failure: "cancelled", reason: "failed"}
      );
      expect(pair.right.diagnostics().incoming).toMatchObject({
        closedPromises: 0,
        occupied: 0,
        reservedBytes: 0,
        responseBytes: 0,
      });
      await pending;
    } finally {
      await Promise.all([pair.left.close(), pair.right.close()]);
    }
  },
  15000
);

instrumented.each(["finish", "fail"] as const)(
  "cancel preserves already latched %s result",
  async (action) => {
    const pair = await incomingPair(() => hooks.networkTestScenario("incoming_hold"));
    try {
      const pending = pair.left.request(pair.remote.peerId, BLOCKS, new Uint8Array(32)).next();
      void pending.catch(() => undefined);
      const incoming = await takeIncoming(pair.right);
      const closed = action === "finish" ? incoming.finish() : incoming.fail(139, new TextEncoder().encode("latched"));
      expect(closed).toBe(incoming.closed);
      if (action === "finish") expect((await pending).done).toBe(true);
      else
        await expect(pending).rejects.toMatchObject({
          peerMessage: new TextEncoder().encode("latched"),
          peerStatus: 139,
        });
      await expect.poll(() => hooks.networkTestIncoming().nativeInbound).toBe(0);
      expect(pair.right.diagnostics().incoming).toMatchObject({closedPromises: 1, occupied: 1, reservedBytes: 0});
      expect(incoming.cancel()).toBe(closed);
      hooks.networkTestIncomingRelease();
      await pair.right.getIdentity();
      expect(await closed).toEqual({chunks: 0, reason: "served"});
      expect(pair.right.diagnostics().incoming.occupied).toBe(0);
    } finally {
      hooks.networkTestIncomingRelease();
      await Promise.all([pair.left.close(), pair.right.close()]);
    }
  },
  15000
);

async function checkReplacement(incoming: NativeIncomingRequest, session: bigint) {
  const replacement = await incomingPair();
  try {
    expect(replacement.right.diagnostics().session).not.toBe(session);
    const stream = replacement.left.request(replacement.remote.peerId, BLOCKS, new Uint8Array(32));
    const read = stream.next();
    void read.catch(() => undefined);
    const next = await takeIncoming(replacement.right);
    const ack = next.respond(new Uint8Array(4000).fill(29), replacement.rightConfig.requestForks[0]);
    expect(incoming.cancel()).toBe(incoming.closed);
    await expect(incoming.respond(new Uint8Array(4000), replacement.rightConfig.requestForks[0])).rejects.toMatchObject(
      {
        code: "NetworkIncomingClosed",
      }
    );
    await ack;
    expect((await read).value?.data).toEqual(new Uint8Array(4000).fill(29));
    const done = stream.next();
    expect(await next.finish()).toEqual({chunks: 1, reason: "served"});
    expect((await done).done).toBe(true);
  } finally {
    await Promise.all([replacement.left.close(), replacement.right.close()]);
  }
}
