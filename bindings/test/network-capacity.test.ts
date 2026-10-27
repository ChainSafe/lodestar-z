import {afterEach, expect, test, vi} from "vitest";
import {PublicationCapacityWaiters, RequestCapacityWaiters} from "../src/network-capacity.js";

afterEach(() => vi.useRealTimers());

test("publication waits follow caller concurrency and clean up on cancellation, timeout and close", async () => {
  vi.useFakeTimers();
  const watch = vi.fn(() => false);
  const waits = new PublicationCapacityWaiters({publicationCapacityWatch: watch});
  const controllers = Array.from({length: 300}, () => new AbortController());
  const pending = controllers.map((controller) =>
    waits.wait("slots", {signal: controller.signal, timeoutMs: 1000}).catch((error) => error.code)
  );
  controllers[0].abort();
  expect(await pending[0]).toBe("NetworkPublicationCapacityCancelled");
  await vi.advanceTimersByTimeAsync(1000);
  expect(await Promise.all(pending.slice(1))).toEqual(Array(299).fill("NetworkPublicationCapacityTimeout"));
  const closing = waits.wait("slots", {signal: controllers[1].signal, timeoutMs: 1000}).catch((error) => error.code);
  waits.close();
  expect(await closing).toBe("NetworkClosed");
  expect(vi.getTimerCount()).toBe(0);
});

test("publication waits observe releases both before and after registration", async () => {
  const watch = vi.fn(() => false);
  const waits = new PublicationCapacityWaiters({publicationCapacityWatch: watch});
  const options = {signal: new AbortController().signal, timeoutMs: 1000};
  const pending = waits.wait("slots", options);
  watch.mockReturnValue(true);
  waits.changed();
  await pending;
  await waits.wait("slots", options);
  waits.close();
});

test("capacity waits recheck their own resource and observe releases before registration", async () => {
  const revisions = {bytes: 0, requests: 0};
  const runtime = {
    requestCapacityWatch: vi.fn((token: string) => revisions[token as keyof typeof revisions] !== 0),
  };
  const waits = new RequestCapacityWaiters(runtime);
  const controller = new AbortController();
  const finished = vi.fn();
  const pending = waits.wait("requests", {signal: controller.signal, timeoutMs: 1000}).then(finished);
  revisions.bytes++;
  waits.changed();
  await Promise.resolve();
  expect(finished).not.toHaveBeenCalled();
  revisions.requests++;
  waits.changed();
  await pending;
  expect(finished).toHaveBeenCalledOnce();
  await waits.wait("bytes", {signal: controller.signal, timeoutMs: 1000});
  waits.close();
});

test("request waits follow caller concurrency and remove cancelled waits immediately", async () => {
  const runtime = {requestCapacityWatch: vi.fn(() => false)};
  const waits = new RequestCapacityWaiters(runtime);
  const controllers = Array.from({length: 300}, () => new AbortController());
  const pending = controllers.map((controller) =>
    waits.wait("requests", {signal: controller.signal, timeoutMs: 1000}).catch((error) => error.code)
  );
  expect(runtime.requestCapacityWatch).toHaveBeenCalledTimes(300);
  for (const controller of controllers) controller.abort();
  expect(await Promise.all(pending)).toEqual(Array(300).fill("NetworkRequestCapacityCancelled"));
  runtime.requestCapacityWatch.mockReturnValue(true);
  await waits.wait("requests", {signal: new AbortController().signal, timeoutMs: 1000});
  waits.close();
});

test("unrelated notifications do not extend the waiting deadline and close rejects waits", async () => {
  vi.useFakeTimers();
  const waits = new RequestCapacityWaiters({requestCapacityWatch: () => false});
  const options = {signal: new AbortController().signal, timeoutMs: 1000};
  const pending = waits.wait("requests", options).catch((error) => error.code);
  await vi.advanceTimersByTimeAsync(500);
  waits.changed();
  await vi.advanceTimersByTimeAsync(500);
  expect(await pending).toBe("NetworkRequestCapacityTimeout");
  const closing = waits.wait("requests", options).catch((error) => error.code);
  waits.close();
  expect(await closing).toBe("NetworkClosed");
  expect(vi.getTimerCount()).toBe(0);
  await expect(waits.wait("requests", options)).rejects.toMatchObject({code: "NetworkClosed"});
});
