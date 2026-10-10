import {describe, expect, it} from "vitest";
import {ACTION_MAX, ActionQueue} from "../src/network-action-queue.js";
import type {NativeAction} from "../src/network-runtime.js";

const handle = (index: number) => ({generation: 1n, index});
const report = (peerId: string, count = 1): NativeAction => ({action: "fatal", count, peerId, type: "reportPeer"});

describe("ActionQueue", () => {
  it("takes obligations first in bounded batches, preserving both arrival orders", () => {
    const queue = new ActionQueue();
    const root = new Uint8Array(32).fill(1);
    queue.enqueue({root, type: "block"});
    queue.enqueue({root, type: "block"});
    for (let i = 0; i < 150; i++) queue.enqueue(report("peer"));
    queue.enqueue({action: "high_tolerance", count: 1, peerId: "peer", type: "reportPeer"});
    queue.enqueue({type: "dropQueued"});
    const obligations: NativeAction[] = Array.from({length: 1000}, (_, i) =>
      i % 2 === 0
        ? {handle: handle(i), type: "verdict", verdict: "accept"}
        : {available: false, handle: handle(i), type: "classify"}
    );
    for (const action of obligations) queue.enqueue(action);
    const batches = Array.from({length: 4}, () => queue.take());
    expect(batches.map((batch) => batch.length)).toEqual([ACTION_MAX, ACTION_MAX, ACTION_MAX, 1000 - 768 + 4]);
    expect(batches.flat()).toEqual([
      ...obligations,
      {root, type: "block"},
      report("peer", 100),
      {action: "high_tolerance", count: 1, peerId: "peer", type: "reportPeer"},
      {type: "dropQueued"},
    ]);
    expect(queue.pending()).toBe(false);
  });

  it("replaces excess roots with one recheck while retaining unrelated actions", () => {
    const queue = new ActionQueue();
    queue.enqueue(report("peer"));
    for (let i = 0; i < 257; i++) queue.enqueue({root: Uint8Array.of(i >> 8, i & 255), type: "block"});
    queue.enqueue({root: new Uint8Array(32), type: "block"});
    queue.enqueue({type: "recheck"});
    expect(queue.take()).toEqual([report("peer"), {type: "recheck"}]);
    queue.enqueue({root: new Uint8Array(32), type: "block"});
    expect(queue.take()).toEqual([{root: new Uint8Array(32), type: "block"}]);
  });

  it("drops peer penalties past 512 entries and reuses the capacity after a take", () => {
    const queue = new ActionQueue();
    for (let i = 0; i < 514; i++) queue.enqueue(report(`peer-${i}`));
    expect(queue.reportsDropped).toBe(2);
    expect(queue.take()).toHaveLength(ACTION_MAX);
    queue.enqueue(report("peer-512"));
    expect(queue.take()).toHaveLength(512 - ACTION_MAX);
    expect(queue.take()).toEqual([report("peer-512")]);
  });
});

it("preserves endpoint evidence and separates reconnects, unknown origins and causes", () => {
  const queue = new ActionQueue();
  const origin = {
    connection: {generation: 1, index: 1},
    endpoint: {address: Uint8Array.of(192, 0, 2, 1), family: 4 as const, port: 9000},
  };
  const action: Extract<NativeAction, {type: "reportPeer"}> = {
    action: "low_tolerance",
    context: {origin, reason: "gossip_validation"},
    count: 1,
    peerId: "peer",
    type: "reportPeer",
  };
  const original = structuredClone(action);
  queue.enqueue(action);
  queue.enqueue(action);
  origin.connection.generation = 2;
  origin.endpoint.address[3] = 2;
  queue.enqueue(action);
  queue.enqueue({...action, context: {...action.context, reason: "gossip_import"}});
  queue.enqueue({...action, context: {reason: "gossip_validation"}});
  const pending = queue.take();
  expect(pending).toHaveLength(4);
  expect(pending[0]).toEqual({...original, count: 2});
  expect(pending[1]).toEqual(action);
  expect(pending[2]).toMatchObject({context: {reason: "gossip_import"}});
  expect(pending[3]).toMatchObject({context: {reason: "gossip_validation"}});
  expect("context" in pending[3] && pending[3].context?.origin).toBeUndefined();
});
