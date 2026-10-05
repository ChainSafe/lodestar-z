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

  it("restores a refused batch ahead of new obligations and merges requests without mutating it", () => {
    const queue = new ActionQueue();
    const first: NativeAction = {handle: handle(1), type: "verdict", verdict: "accept"};
    const next: NativeAction = {available: true, handle: handle(2), type: "classify"};
    queue.enqueue(first);
    queue.enqueue(report("peer", 60));
    const batch = queue.take();
    queue.enqueue(next);
    queue.enqueue(report("peer", 70));
    queue.enqueue({type: "dropQueued"});
    queue.restore(batch);
    expect(batch).toEqual([first, report("peer", 60)]);
    expect(queue.take()).toEqual([first, next, report("peer", 100), {type: "dropQueued"}]);
    queue.restore(batch);
    queue.enqueue(report("peer", 1));
    expect(batch).toEqual([first, report("peer", 60)]);
    expect(queue.take()).toEqual([first, report("peer", 61)]);
  });
});
