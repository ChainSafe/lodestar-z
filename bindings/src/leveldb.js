import bindings from "./bindings.js";

const MAX_BYTES = 1024 * 1024 * 1024;
const MAX_PAGE_ENTRIES = 1024;
const MAX_BATCH_ENTRIES = 16_777_216;
const MAX_LIMIT = 0xffffffff;

function failure(code) {
  return Object.assign(new Error(code), {code});
}

function readLimit(value, maximum, minimum = 0) {
  if (value === undefined) return maximum;
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw failure("InvalidLimit");
  return value;
}

function completion(resolve, reject) {
  return (error, value) => {
    if (error === null) resolve(value);
    else reject(error);
  };
}

function submit(native, method, args = []) {
  return new Promise((resolve, reject) => {
    native[method](...args, completion(resolve, reject));
  });
}

export class LevelDb {
  #native = new bindings.NativeLevelDb();
  #closing;

  static async open(path, options = {}) {
    const database = new LevelDb();
    try {
      await submit(database.#native, "open", [path, options]);
      return database;
    } catch (error) {
      try {
        await submit(database.#native, "close");
      } catch (cleanupError) {
        throw new AggregateError([error, cleanupError], "LevelDB open cleanup failed");
      }
      throw error;
    }
  }

  #assertOpen() {
    if (this.#closing !== undefined) throw failure("DatabaseClosed");
  }

  async get(key, options = {}) {
    this.#assertOpen();
    const maxValueBytes = readLimit(options.maxValueBytes, MAX_BYTES);
    const values = await submit(this.#native, "getMany", [
      [key],
      maxValueBytes,
      maxValueBytes,
      options.fillCache ?? true,
    ]);
    return values[0];
  }

  async getMany(keys, options = {}) {
    this.#assertOpen();
    const maxValueBytes = readLimit(options.maxValueBytes, MAX_BYTES);
    const maxTotalBytes = readLimit(options.maxTotalBytes, MAX_BYTES);
    return submit(this.#native, "getMany", [keys, maxValueBytes, maxTotalBytes, options.fillCache ?? true]);
  }

  async put(key, value, options = {}) {
    this.#assertOpen();
    if (value === null) throw failure("InvalidBytes");
    return submit(this.#native, "write", [[key], [value], options.sync ?? false]);
  }

  async del(key, options = {}) {
    this.#assertOpen();
    return submit(this.#native, "write", [[key], [null], options.sync ?? false]);
  }

  async batch(operations, options = {}) {
    this.#assertOpen();
    if (!Array.isArray(operations)) throw failure("InvalidBatchOperation");
    const length = operations.length;
    if (length > MAX_BATCH_ENTRIES) throw failure("BatchTooLarge");
    const keys = [];
    const values = [];
    for (let index = 0; index < length; index++) {
      const operation = operations[index];
      const type = operation?.type;
      if (type !== "put" && type !== "del") throw failure("InvalidBatchOperation");
      const value = type === "put" ? operation.value : null;
      if (type === "put" && value === null) throw failure("InvalidBytes");
      keys.push(operation.key);
      values.push(value);
    }
    return submit(this.#native, "write", [keys, values, options.sync ?? false]);
  }

  iterator(options = {}) {
    return this.#iterator(options, "entries");
  }

  keys(options = {}) {
    return this.#iterator(options, "keys");
  }

  values(options = {}) {
    return this.#iterator(options, "values");
  }

  #iterator(options, projection) {
    this.#assertOpen();
    const maxValueBytes = readLimit(options.maxValueBytes, MAX_BYTES, 1);
    const maxTotalBytes = readLimit(options.maxTotalBytes, MAX_BYTES, 1);
    const maxEntries = readLimit(options.maxEntries, MAX_PAGE_ENTRIES, 1);
    const limit = readLimit(options.limit, MAX_LIMIT);
    const cursor = submit(this.#native, "cursor", [
      {
        fillCache: options.fillCache ?? false,
        gt: options.gt ?? null,
        gte: options.gte ?? null,
        keys: projection === "entries" ? (options.keys ?? true) : projection === "keys",
        limit,
        lt: options.lt ?? null,
        lte: options.lte ?? null,
        reverse: options.reverse ?? false,
        values: projection === "entries" ? (options.values ?? true) : projection === "values",
      },
    ]);
    return new LevelDbIterator(
      this.#native,
      cursor,
      () => this.#closing,
      maxValueBytes,
      maxTotalBytes,
      maxEntries,
      projection
    );
  }

  async clear() {
    this.#assertOpen();
    return submit(this.#native, "clear");
  }

  async approximateSize(start, end) {
    this.#assertOpen();
    return submit(this.#native, "approximateSize", [start, end]);
  }

  async compactRange(start, end) {
    this.#assertOpen();
    return submit(this.#native, "compactRange", [start, end]);
  }

  async getProperty(name) {
    this.#assertOpen();
    return submit(this.#native, "property", [name]);
  }

  static async destroy(path) {
    const native = new bindings.NativeLevelDb();
    try {
      await submit(native, "destroy", [path]);
    } catch (error) {
      try {
        await submit(native, "close");
      } catch (cleanupError) {
        throw new AggregateError([error, cleanupError], "LevelDB destroy cleanup failed");
      }
      throw error;
    }
    await submit(native, "close");
  }

  close() {
    this.#closing ??= this.#close().catch((error) => {
      this.#closing = undefined;
      throw error;
    });
    return this.#closing;
  }

  async #close() {
    await submit(this.#native, "close");
  }
}

class LevelDbIterator {
  #native;
  #cursor;
  #databaseClosing;
  #maxValueBytes;
  #maxTotalBytes;
  #maxEntries;
  #projection;
  #entries = [];
  #index = 0;
  #pageDone = false;
  #finished = false;
  #busy = false;
  #closing;

  constructor(native, cursor, databaseClosing, maxValueBytes, maxTotalBytes, maxEntries, projection) {
    this.#native = native;
    this.#cursor = cursor.then(
      (id) => ({id}),
      (error) => ({error})
    );
    this.#databaseClosing = databaseClosing;
    this.#maxValueBytes = maxValueBytes;
    this.#maxTotalBytes = maxTotalBytes;
    this.#maxEntries = maxEntries;
    this.#projection = projection;
  }

  [Symbol.asyncIterator]() {
    return this;
  }

  async next() {
    if (this.#busy) throw failure("IteratorBusy");
    if (this.#finished) return {done: true, value: undefined};
    this.#busy = true;
    try {
      if (this.#databaseClosing() !== undefined) throw failure("DatabaseClosed");
      if (this.#index === this.#entries.length) {
        const cursor = await this.#cursor;
        if ("error" in cursor) throw cursor.error;
        if (this.#finished) return {done: true, value: undefined};
        if (this.#databaseClosing() !== undefined) throw failure("DatabaseClosed");
        const page = await submit(this.#native, "readCursor", [
          cursor.id,
          this.#maxValueBytes,
          this.#maxTotalBytes,
          this.#maxEntries,
        ]);
        if (this.#finished) return {done: true, value: undefined};
        if (this.#databaseClosing() !== undefined) throw failure("DatabaseClosed");
        this.#entries = page.entries;
        this.#index = 0;
        this.#pageDone = page.done;
        if (this.#entries.length === 0) {
          if (!this.#pageDone) throw failure("InvalidCursorPage");
          await this.close();
          return {done: true, value: undefined};
        }
      }
      const value = this.#entries[this.#index];
      this.#entries[this.#index++] = undefined;
      if (this.#index === this.#entries.length && this.#pageDone) await this.close();
      return {
        done: false,
        value: this.#projection === "keys" ? value.key : this.#projection === "values" ? value.value : value,
      };
    } catch (error) {
      try {
        await this.close();
      } catch (cleanupError) {
        throw new AggregateError([error, cleanupError], "LevelDB iterator cleanup failed");
      }
      throw error;
    } finally {
      this.#busy = false;
    }
  }

  close() {
    this.#finished = true;
    this.#entries = [];
    this.#index = 0;
    this.#closing ??= this.#close().catch((error) => {
      this.#closing = undefined;
      throw error;
    });
    return this.#closing;
  }

  async #close() {
    const cursor = await this.#cursor;
    if ("error" in cursor) return;
    const closing = this.#databaseClosing();
    if (closing !== undefined) await closing;
    else if (!this.#pageDone) await submit(this.#native, "closeCursor", [cursor.id]);
  }

  async return() {
    await this.close();
    return {done: true, value: undefined};
  }

  async throw(error) {
    await this.close();
    throw error;
  }
}
