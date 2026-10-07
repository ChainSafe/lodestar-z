import {vi} from "vitest";

export class Escalated extends Error {}

export function immediates(): (() => void)[] {
  const queued: (() => void)[] = [];
  const hold = (callback: (...args: unknown[]) => void, ...args: unknown[]) => {
    queued.push(() => callback(...args));
  };
  vi.spyOn(globalThis, "setImmediate").mockImplementation(hold as unknown as typeof setImmediate);
  return queued;
}

export function runUntilEscalated(queued: (() => void)[], max: number): boolean {
  for (let i = 0; i < max && queued.length > 0; i++) {
    try {
      queued.shift()?.();
    } catch (error) {
      if (error instanceof Escalated) return true;
      throw error;
    }
  }
  return false;
}
