import {mkdtemp, rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {expect, it} from "vitest";
import {
  LevelDb,
  type LevelDbEntry,
  type LevelDbIterator,
  type LevelDbOperation,
  type LevelDbOptions,
} from "../src/leveldb.js";

const MAX_BYTES = 1024 * 1024 * 1024;
const MAX_BATCH_ENTRIES = 16_777_216;
const READ = {maxValueBytes: 64};
const READ_MANY = {maxTotalBytes: 64, maxValueBytes: 64};
const PAGE = {maxEntries: 1, maxTotalBytes: 64, maxValueBytes: 64};

function bytes(...values: number[]): Uint8Array {
  return Uint8Array.from(values);
}

async function withDatabase(
  run: (database: LevelDb, path: string) => Promise<void>,
  options?: LevelDbOptions
): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "lodestar-leveldb-"));
  let database: LevelDb | undefined;
  try {
    const path = join(directory, "db");
    database = await LevelDb.open(path, options);
    await run(database, path);
  } finally {
    try {
      await database?.close();
    } finally {
      await rm(directory, {force: true, recursive: true});
    }
  }
}

async function collect(iterator: LevelDbIterator): Promise<LevelDbEntry[]> {
  const entries: LevelDbEntry[] = [];
  try {
    for (let count = 0; count < 16; count++) {
      const next = await iterator.next();
      if (next.done) return entries;
      entries.push(next.value);
    }
    throw new Error("Test iterator exceeded 16 entries");
  } finally {
    await iterator.close();
  }
}

it("persists binary keys, empty values, ordered batches, and deletions across reopen", async () => {
  await withDatabase(async (db, path) => {
    expect(await db.get(bytes(9), READ)).toBeNull();
    await db.put(bytes(), bytes(), {sync: true});
    await db.batch(
      [
        {key: bytes(0, 255), type: "put", value: bytes(3, 4)},
        {key: bytes(1), type: "put", value: bytes(5)},
        {key: bytes(1), type: "del"},
        {key: bytes(1), type: "put", value: bytes(6)},
      ],
      {sync: true}
    );
    expect(await db.get(bytes(), {maxValueBytes: 0})).toEqual(bytes());
    expect(
      await db.getMany([bytes(0, 255), bytes(9), bytes(), bytes(0, 255)], {maxTotalBytes: 4, maxValueBytes: 2})
    ).toEqual([bytes(3, 4), null, bytes(), bytes(3, 4)]);
    expect(await db.getMany([], {maxTotalBytes: 0, maxValueBytes: 0})).toEqual([]);
    await db.batch([]);
    await db.del(bytes(9));
    await db.del(bytes(1), {sync: true});
    await db.close();
    const reopened = await LevelDb.open(path, {createIfMissing: false});
    try {
      expect(await reopened.get(bytes(0, 255), READ)).toEqual(bytes(3, 4));
      expect(await reopened.get(bytes(), {maxValueBytes: 0})).toEqual(bytes());
      expect(await reopened.get(bytes(1), READ)).toBeNull();
    } finally {
      await reopened.close();
    }
  });
});

it("copies offset input views before returning and gives callers independent values", async () => {
  await withDatabase(async (db) => {
    const key = bytes(99, 1, 2, 99).subarray(1, 3);
    const value = Buffer.from([99, 3, 4, 99]).subarray(1, 3);
    const writing = db.put(key, value);
    key.fill(7);
    value.fill(8);
    await writing;
    const query = bytes(1, 2);
    const reading = db.get(query, READ);
    query.fill(9);
    const result = await reading;
    expect(result).toEqual(bytes(3, 4));
    if (result === null) throw new Error("Missing copied value");
    result.fill(10);
    expect(await db.get(bytes(1, 2), READ)).toEqual(bytes(3, 4));
    const batchKey = bytes(5);
    const batchValue = bytes(6);
    const operations: LevelDbOperation[] = [{key: batchKey, type: "put", value: batchValue}];
    const batching = db.batch(operations);
    batchKey.fill(7);
    batchValue.fill(8);
    operations.length = 0;
    await batching;
    expect(await db.get(bytes(5), READ)).toEqual(bytes(6));
    const keys = [bytes(5), bytes(5)];
    const many = db.getMany(keys, {maxTotalBytes: 2, maxValueBytes: 1});
    keys[0].fill(9);
    keys.length = 0;
    const values = await many;
    expect(values).toEqual([bytes(6), bytes(6)]);
    values[0]?.fill(10);
    expect(values[1]).toEqual(bytes(6));
    expect(await db.get(bytes(5), READ)).toEqual(bytes(6));
  });
});

it("validates an entire batch before mutation and rejects malformed byte inputs", async () => {
  await withDatabase(async (db) => {
    await db.put(bytes(1), bytes(7));
    await expect(
      db.batch([
        {key: bytes(1), type: "put", value: bytes(8)},
        {key: new Uint8Array(4097), type: "del"},
      ])
    ).rejects.toThrow("KeyTooLarge");
    await expect(
      db.batch([
        {key: bytes(1), type: "del"},
        {key: bytes(2), type: "put", value: null as unknown as Uint8Array},
      ])
    ).rejects.toThrow("InvalidBytes");
    await expect(db.put(bytes(1), null as unknown as Uint8Array)).rejects.toThrow("InvalidBytes");
    await expect(db.get(new Uint16Array(1) as unknown as Uint8Array, READ)).rejects.toThrow("InvalidBytes");
    await expect(db.batch([{key: bytes(1), type: "clear"} as unknown as LevelDbOperation])).rejects.toThrow(
      "InvalidBatchOperation"
    );
    await expect(db.batch(new Array<LevelDbOperation>(MAX_BATCH_ENTRIES + 1))).rejects.toThrow("BatchTooLarge");
    await expect(db.getMany(new Array<Uint8Array>(MAX_BATCH_ENTRIES + 1), READ_MANY)).rejects.toThrow("BatchTooLarge");
    expect(await db.get(bytes(1), READ)).toEqual(bytes(7));
    const largestKey = new Uint8Array(4096).fill(255);
    await db.put(largestKey, bytes(2));
    expect(await db.get(largestKey, READ)).toEqual(bytes(2));
    await expect(db.get(new Uint8Array(4097), READ)).rejects.toThrow("KeyTooLarge");
  });
});

it("rejects values and aggregate batches beyond the hard byte limit before mutation", async () => {
  await withDatabase(async (db) => {
    const oversized = new Uint8Array(MAX_BYTES + 1);
    await expect(db.put(bytes(1), oversized)).rejects.toThrow("ValueTooLarge");
    await expect(
      db.batch([
        {key: bytes(2), type: "put", value: bytes(3)},
        ...Array.from(
          {length: 4},
          (): LevelDbOperation => ({
            key: bytes(),
            type: "put",
            value: oversized.subarray(0, MAX_BYTES),
          })
        ),
      ])
    ).rejects.toThrow("BatchTooLarge");
    expect(await db.get(bytes(1), READ)).toBeNull();
    expect(await db.get(bytes(2), READ)).toBeNull();
  });
});

it("enforces per-value and aggregate read bounds without poisoning subsequent reads", async () => {
  await withDatabase(async (db) => {
    await db.batch([
      {key: bytes(1), type: "put", value: bytes(2, 3)},
      {key: bytes(4), type: "put", value: bytes(5, 6)},
    ]);
    await expect(db.get(bytes(1), {maxValueBytes: 1})).rejects.toThrow("ValueTooLarge");
    await expect(db.getMany([bytes(1), bytes(4)], {maxTotalBytes: 3, maxValueBytes: 2})).rejects.toThrow(
      "BatchTooLarge"
    );
    expect(await db.getMany([bytes(1), bytes(4)], {maxTotalBytes: 4, maxValueBytes: 2})).toEqual([
      bytes(2, 3),
      bytes(5, 6),
    ]);
    for (const invalid of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, MAX_BYTES + 1]) {
      await expect(db.get(bytes(1), {maxValueBytes: invalid})).rejects.toThrow("InvalidLimit");
      await expect(db.getMany([], {maxTotalBytes: invalid, maxValueBytes: 1})).rejects.toThrow("InvalidLimit");
    }
    for (const invalid of [0, -1, 1.5, 1025]) {
      expect(() => db.iterator({...PAGE, maxEntries: invalid})).toThrow("InvalidLimit");
    }
    expect(() => db.iterator({...PAGE, maxTotalBytes: 0})).toThrow("InvalidLimit");
    expect(() => db.iterator({...PAGE, maxValueBytes: 0})).toThrow("InvalidLimit");
    expect(() => db.iterator({...PAGE, limit: -1})).toThrow("InvalidLimit");
    expect(() => db.iterator({...PAGE, limit: 0x100000000})).toThrow("InvalidLimit");
  });
});

it("iterates byte-sorted half-open ranges with page and total row limits", async () => {
  await withDatabase(async (db) => {
    const keys = [bytes(255), bytes(1), bytes(0, 255), bytes(0, 0), bytes(0), bytes()];
    await db.batch(keys.map((key) => ({key, type: "put", value: bytes(9)})));
    expect((await collect(db.iterator(PAGE))).map(({key}) => key)).toEqual(keys.slice().reverse());
    const options = {gte: bytes(0), lt: bytes(1), maxEntries: 1, maxTotalBytes: 3, maxValueBytes: 1};
    expect((await collect(db.iterator(options))).map(({key}) => key)).toEqual([bytes(0), bytes(0, 0), bytes(0, 255)]);
    expect((await collect(db.iterator({...options, limit: 2}))).map(({key}) => key)).toEqual([bytes(0), bytes(0, 0)]);
    expect(await collect(db.iterator({...options, limit: 0}))).toEqual([]);
    expect(await collect(db.iterator({...PAGE, gte: bytes(2), lt: bytes(1)}))).toEqual([]);
  });
});

it("takes its snapshot and copies range bounds at iterator creation before the first pull", async () => {
  await withDatabase(async (db) => {
    await db.put(bytes(1), bytes(11));
    const beforeSnapshot = db.put(bytes(2), bytes(22));
    const gte = bytes(1);
    const lt = bytes(3);
    const iterator = db.iterator({...PAGE, gte, lt});
    gte.fill(9);
    lt.fill(0);
    const afterSnapshot = db.batch([
      {key: bytes(1), type: "del"},
      {key: bytes(2), type: "put", value: bytes(33)},
      {key: bytes(3), type: "put", value: bytes(44)},
    ]);
    await Promise.all([beforeSnapshot, afterSnapshot]);
    const entries = await collect(iterator);
    expect(entries).toEqual([
      {key: bytes(1), value: bytes(11)},
      {key: bytes(2), value: bytes(22)},
    ]);
    expect(await db.get(bytes(2), READ)).toEqual(bytes(33));
    entries[1].value.fill(0);
    expect(await db.get(bytes(2), READ)).toEqual(bytes(33));
  });
});

it("releases cursors on early return, exhaustion, cancellation before opening, and read errors", async () => {
  await withDatabase(async (db) => {
    await db.batch([
      {key: bytes(1), type: "put", value: bytes(2)},
      {key: bytes(3), type: "put", value: bytes(4, 5, 6)},
    ]);
    for (let count = 0; count < 65; count++) {
      for await (const entry of db.iterator(PAGE)) {
        expect(entry.key).toEqual(bytes(1));
        break;
      }
      const unstarted = db.iterator(PAGE);
      const closing = unstarted.close();
      expect(unstarted.close()).toBe(closing);
      await closing;
      expect(await unstarted.next()).toEqual({done: true, value: undefined});
      expect((await collect(db.iterator({...PAGE, limit: 1}))).length).toBe(1);
      const oversized = db.iterator({...PAGE, maxValueBytes: 1});
      expect((await oversized.next()).value).toEqual({key: bytes(1), value: bytes(2)});
      await expect(oversized.next()).rejects.toThrow("ValueTooLarge");
      expect(await oversized.next()).toEqual({done: true, value: undefined});
      const pageTooSmall = db.iterator({...PAGE, maxTotalBytes: 1});
      await expect(pageTooSmall.next()).rejects.toThrow("BatchTooLarge");
    }
    expect((await collect(db.iterator(PAGE))).length).toBe(2);
  });
}, 15000);

it("allows only one pending pull and cleans up a pull cancelled before the cursor opens", async () => {
  await withDatabase(async (db) => {
    await db.put(bytes(1), bytes(2));
    const iterator = db.iterator(PAGE);
    const first = iterator.next();
    await expect(iterator.next()).rejects.toThrow("IteratorBusy");
    expect(await first).toEqual({done: false, value: {key: bytes(1), value: bytes(2)}});
    await iterator.close();
    const cancelled = db.iterator(PAGE);
    const pending = cancelled.next();
    const returning = cancelled.return();
    expect(await pending).toEqual({done: true, value: undefined});
    expect(await returning).toEqual({done: true, value: undefined});
    const thrown = db.iterator(PAGE);
    const error = new Error("stop iteration");
    await expect(thrown.throw(error)).rejects.toBe(error);
    expect(await thrown.next()).toEqual({done: true, value: undefined});
  });
});

it("rejects excess pending operations immediately and admits later work after settlement", async () => {
  await withDatabase(
    async (db) => {
      const accepted = db.put(bytes(1), bytes(2));
      const rejected = db.put(bytes(3), bytes(4));
      await expect(rejected).rejects.toThrow("PendingOperationsExceeded");
      await accepted;
      await db.put(bytes(3), bytes(4));
      expect(await db.get(bytes(3), READ)).toEqual(bytes(4));
    },
    {maxPendingOperations: 1}
  );
});

it("bounds copied pending inputs and keeps output limits separate from admission", async () => {
  await withDatabase(
    async (db) => {
      const value = new Uint8Array(3072).fill(7);
      const accepted = db.put(bytes(1), value);
      const rejected = db.put(bytes(2), value);
      await expect(rejected).rejects.toThrow("PendingBytesExceeded");
      await accepted;
      await db.put(bytes(2), value);
      expect(await db.get(bytes(2))).toEqual(value);
      expect(await Promise.all([db.get(bytes(3)), db.get(bytes(4))])).toEqual([null, null]);
    },
    {maxPendingBytes: 4096}
  );
});

it("closes cursors and databases despite saturated admission and persists accepted writes", async () => {
  await withDatabase(
    async (db, path) => {
      await db.batch([
        {key: bytes(1), type: "put", value: bytes(2)},
        {key: bytes(3), type: "put", value: bytes(4)},
      ]);
      const iterator = db.iterator(PAGE);
      await iterator.next();
      const writing = db.put(bytes(5), bytes(6));
      await Promise.all([writing, iterator.close()]);
      const abandoned = db.iterator(PAGE);
      await abandoned.next();
      const lastWrite = db.put(bytes(7), bytes(8), {sync: true});
      const closing = db.close();
      expect(db.close()).toBe(closing);
      await expect(db.put(bytes(9), bytes(10))).rejects.toThrow("DatabaseClosed");
      await expect(db.get(bytes(1), READ)).rejects.toThrow("DatabaseClosed");
      expect(() => db.iterator(PAGE)).toThrow("DatabaseClosed");
      await Promise.all([lastWrite, closing]);
      await expect(abandoned.next()).rejects.toThrow("DatabaseClosed");
      await abandoned.close();
      const reopened = await LevelDb.open(path, {createIfMissing: false});
      try {
        expect(await reopened.get(bytes(7), READ)).toEqual(bytes(8));
        expect(await reopened.get(bytes(9), READ)).toBeNull();
      } finally {
        await reopened.close();
      }
    },
    {maxPendingOperations: 1}
  );
});

it("enforces the live cursor cap and reuses capacity after explicit close", async () => {
  await withDatabase(async (db) => {
    await db.batch([
      {key: bytes(1), type: "put", value: bytes(2)},
      {key: bytes(3), type: "put", value: bytes(4)},
    ]);
    const cursors: LevelDbIterator[] = [];
    try {
      for (let index = 0; index < 64; index++) {
        const cursor = db.iterator(PAGE);
        cursors.push(cursor);
        expect((await cursor.next()).value).toEqual({key: bytes(1), value: bytes(2)});
      }
      const excess = db.iterator(PAGE);
      await expect(excess.next()).rejects.toThrow("CursorCapacity");
      await excess.close();
      await cursors[0].close();
      const replacement = db.iterator(PAGE);
      cursors[0] = replacement;
      expect((await replacement.next()).value).toEqual({key: bytes(1), value: bytes(2)});
    } finally {
      await Promise.all(cursors.map((cursor) => cursor.close()));
    }
  });
});

it("rejects shared and detached buffers before changing stored data", async () => {
  await withDatabase(async (db) => {
    const key = bytes(1);
    await db.put(key, bytes(2));
    const shared = new Uint8Array(new SharedArrayBuffer(1));
    await expect(db.put(key, shared)).rejects.toThrow("InvalidBytes");
    await expect(db.get(shared, READ)).rejects.toThrow("InvalidBytes");
    const backing = new ArrayBuffer(1);
    const detached = new Uint8Array(backing);
    structuredClone(backing, {transfer: [backing]});
    await expect(db.put(key, detached)).rejects.toThrow("InvalidBytes");
    await expect(db.get(detached, READ)).rejects.toThrow("InvalidBytes");
    expect(await db.get(key, READ)).toEqual(bytes(2));
  });
});

for (const terminalError of [false, true]) {
  it(`reserves cursor cleanup for new snapshots after 64 ${terminalError ? "terminal errors" : "explicit closes"}`, async () => {
    await withDatabase(
      async (db) => {
        await db.batch([
          {key: bytes(1), type: "put", value: bytes(1)},
          {key: bytes(2), type: "put", value: bytes(2, 2)},
        ]);
        const old: LevelDbIterator[] = [];
        const fresh: LevelDbIterator[] = [];
        try {
          for (let index = 0; index < 64; index++) {
            const cursor = db.iterator({...PAGE, maxValueBytes: terminalError ? 1 : 2});
            old.push(cursor);
            await cursor.next();
          }
          const terminal = old.map((cursor) =>
            terminalError ? expect(cursor.next()).rejects.toThrow("ValueTooLarge") : cursor.close()
          );
          await Promise.resolve();
          for (let index = 0; index < 64; index++) fresh.push(db.iterator(PAGE));
          await Promise.all(terminal);
          await Promise.all(fresh.map((cursor) => cursor.next()));
          await Promise.all(fresh.map((cursor) => cursor.close()));
          expect((await collect(db.iterator(PAGE))).length).toBe(2);
        } finally {
          await Promise.all([...old, ...fresh].map((cursor) => cursor.close()));
        }
      },
      {maxPendingOperations: 128}
    );
  });
}

it("validates byte views after all array getters have run", async () => {
  await withDatabase(async (db) => {
    const backing = new ArrayBuffer(1);
    const first = new Uint8Array(backing);
    const keys = [first, bytes(2)];
    Object.defineProperty(keys, 1, {
      get() {
        structuredClone(backing, {transfer: [backing]});
        return bytes(2);
      },
    });
    await expect(db.getMany(keys, READ_MANY)).rejects.toThrow("InvalidBytes");
    await db.put(bytes(3), bytes(4));
    expect(await db.get(bytes(3), READ)).toEqual(bytes(4));
  });
});
