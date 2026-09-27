import {describe, expect, it, vi} from "vitest";
import type {NativeCompletion} from "../src/network-runtime.js";
import {CompletionOwner} from "../src/network-tickets.js";

class Breached extends Error {}

/** An owner over a native stand-in whose next exchange delivers `completions` and `closed`. */
function owner() {
  const next: {completions: NativeCompletion[]; closed: unknown} = {closed: null, completions: []};
  const native = {
    abandon: vi.fn(),
    exchange: vi.fn(() => {
      const result = {closed: next.closed, completions: next.completions, more: false};
      next.completions = [];
      next.closed = null;
      return result;
    }),
    fail: vi.fn((_site: string, reason: string): never => {
      throw new Breached(reason);
    }),
    getState: () => native.state,
    state: "running",
  };
  const completions = new CompletionOwner(native, () => true);
  completions.size({command: 2, publication: 2});
  return {
    completions,
    deliver(delivered: NativeCompletion[], closed: unknown = null) {
      next.completions = delivered;
      next.closed = closed;
      return completions.exchange([], {});
    },
    native,
  };
}

const handle = (index: number, generation: bigint) => ({generation, index});

describe("completion owner", () => {
  it("installs a record before admission returns, and clears it as its completion settles it", async () => {
    const node = owner();
    const published = node.completions.admit("publication", undefined, () => handle(1, 1n));
    node.deliver([{family: "publication", handle: handle(1, 1n), value: "sent"}]);
    // The same completion again finds no record: settling cleared it.
    expect(() => node.deliver([{family: "publication", handle: handle(1, 1n), value: "sent"}])).toThrow(Breached);
    expect(await published).toBe("sent");
    const failed = node.completions.admit("publication", undefined, () => handle(1, 2n));
    node.deliver([{error: "NetworkClosed", family: "publication", handle: handle(1, 2n)}]);
    await expect(failed).rejects.toBe("NetworkClosed");
  });

  it("ignores a completion for a generation older than its slot's, which a replacement record keeps", async () => {
    const node = owner();
    const first = node.completions.admit("command", "getPeers", () => handle(0, 1n));
    node.deliver([{family: "command", handle: handle(0, 1n), kind: "getPeers", value: 1}]);
    const replacement = node.completions.admit("command", "connect", () => handle(0, 2n));
    node.deliver([{family: "command", handle: handle(0, 1n), kind: "getPeers", value: 2}]);
    node.deliver([{family: "command", handle: handle(0, 2n), kind: "connect", value: 3}]);
    expect(await Promise.all([first, replacement])).toEqual([1, 3]);
    expect(node.native.fail).not.toHaveBeenCalled();
  });

  it.each([
    ["a generation never admitted", [{family: "publication", handle: handle(0, 1n), value: 1}]],
    ["a kind the record does not expect", [{family: "command", handle: handle(1, 1n), kind: "connect", value: 1}]],
    ["an index past the family's cells", [{family: "publication", handle: handle(2, 1n), value: 1}]],
    ["a family without records", [{family: "request", handle: handle(0, 1n), value: 1}]],
  ] as [string, NativeCompletion[]][])("breaches the completion contract for %s", (_, delivered) => {
    const node = owner();
    void node.completions.admit("command", "getPeers", () => handle(1, 1n));
    expect(() => node.deliver(delivered)).toThrow(Breached);
    expect(node.native.fail.mock.calls[0][0]).toBe("completion_contract");
    expect(node.native.fail.mock.calls[0][1]).toMatch(/^completed \w+ \d+:1$/);
  });

  it("breaches the completion contract for a live slot or a generation that did not grow", () => {
    const node = owner();
    void node.completions.admit("publication", undefined, () => handle(0, 2n));
    expect(() => node.completions.admit("publication", undefined, () => handle(0, 3n))).toThrow(Breached);
    node.deliver([{family: "publication", handle: handle(0, 2n), value: 1}]);
    expect(() => node.completions.admit("publication", undefined, () => handle(0, 2n))).toThrow(Breached);
    expect(node.native.fail).toHaveBeenLastCalledWith("completion_contract", "admitted publication 0:2");
  });

  it("creates no record for a submission that throws, so close finds none missing", () => {
    const node = owner();
    const refused = new Error("PublicationQueueFull");
    expect(() =>
      node.completions.admit("publication", undefined, () => {
        throw refused;
      })
    ).toThrow(refused);
    expect(node.deliver([], {reason: "requested"}).closed).toEqual({reason: "requested"});
    expect(node.native.fail).not.toHaveBeenCalled();
  });

  it("breaches the completion contract when native closes with a record still live", () => {
    const node = owner();
    void node.completions.admit("publication", undefined, () => handle(0, 1n));
    expect(() => node.deliver([], {reason: "requested"})).toThrow(Breached);
    expect(node.native.fail).toHaveBeenCalledExactlyOnceWith("completion_contract", "closed with records unsettled: 1");
  });

  it("escalates a completion delivered before its record, which native's synchronous admission rules out", () => {
    const node = owner();
    expect(() =>
      node.completions.admit("publication", undefined, () => {
        node.deliver([{family: "publication", handle: handle(0, 1n), value: 1}]);
        return handle(0, 1n);
      })
    ).toThrow(Breached);
  });

  it("holds itself and the event loop from native's last notification until the close result, never after it", () => {
    vi.useFakeTimers({toFake: ["setInterval", "clearInterval"]});
    try {
      const node = owner();
      node.completions.notifier();
      expect(vi.getTimerCount()).toBe(0);
      node.native.state = "closed";
      node.completions.notifier();
      node.completions.notifier();
      expect(vi.getTimerCount()).toBe(1);
      node.deliver([], {reason: "requested"});
      expect(vi.getTimerCount()).toBe(0);
      // A last notification that arrives after an exchange already delivered the close holds nothing.
      node.completions.notifier();
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});
