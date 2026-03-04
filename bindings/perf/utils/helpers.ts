import type {BufferLike} from "./types.js";

function toHexString(bytes: BufferLike): string {
  if (typeof bytes === "string") return bytes;
  if (bytes instanceof Buffer) return bytes.toString("hex");
  if (bytes instanceof Uint8Array) return Buffer.from(bytes).toString("hex");
  if (typeof bytes.toBytes === "function") return Buffer.from(bytes.toBytes()).toString("hex");
  throw Error("toHexString only accepts BufferLike types");
}

export function toHex(bytes: BufferLike): string {
  const hex = toHexString(bytes);
  if (hex.startsWith("0x")) return hex;
  return `0x${hex}`;
}

export function fromHex(hexString: string): Buffer {
  return Buffer.from(hexString.startsWith("0x") ? hexString.slice(2) : hexString, "hex");
}

export function isEqualBytes(value: BufferLike, expected: BufferLike): boolean {
  return toHex(value) === toHex(expected);
}

export function getFilledUint8(length: number, fillWith: string | number | Buffer = "*"): Uint8Array {
  return Uint8Array.from(Buffer.alloc(length, fillWith));
}

export function sullyUint8Array(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(
    Buffer.from([...Uint8Array.prototype.slice.call(bytes, 8), ...Buffer.from("0123456789abcdef", "hex")])
  );
}

export function arrayOfIndexes(start: number, end: number): number[] {
  const arr: number[] = [];
  for (let i = start; i <= end; i++) arr.push(i);
  return arr;
}

export function shuffle<T>(array: T[]): T[] {
  let currentIndex = array.length,
    randomIndex: number;

  while (currentIndex !== 0) {
    randomIndex = Math.floor(Math.random() * currentIndex);
    currentIndex--;

    [array[currentIndex], array[randomIndex]] = [array[randomIndex], array[currentIndex]];
  }

  return array;
}

export function chunkifyMaximizeChunkSize<T>(arr: T[], minPerChunk: number): T[][] {
  const chunkCount = Math.floor(arr.length / minPerChunk);
  if (chunkCount <= 1) {
    return [arr];
  }

  // Prefer less chunks of bigger size
  const perChunk = Math.ceil(arr.length / chunkCount);
  const arrArr: T[][] = [];

  for (let i = 0; i < arr.length; i += perChunk) {
    arrArr.push(arr.slice(i, i + perChunk));
  }

  return arrArr;
}
