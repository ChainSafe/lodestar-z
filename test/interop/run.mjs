import assert from "node:assert/strict";
import {spawn} from "node:child_process";
import {access, stat} from "node:fs/promises";
import {relative, resolve} from "node:path";
import {setTimeout as delay} from "node:timers/promises";
import {MAX, TOPIC, payload, summary} from "./codec.mjs";
import {exerciseRaw} from "./raw_cases.mjs";

const root = resolve(new URL("../..", import.meta.url).pathname);
const lineMax = 65536;
const linesMax = 1024;
const stderrMax = 16 * 1024 * 1024;
const pendingMax = 32;
const suiteController = new AbortController();
const suiteSignal = AbortSignal.any([suiteController.signal, AbortSignal.timeout(180000)]);
const children = new Set();

suiteSignal.addEventListener("abort", () => {
  for (const child of children) child.abort(Error("interop suite timeout"));
});

class Child {
  constructor(name, program, args) {
    this.name = name;
    this.nextId = 1;
    this.pending = new Map();
    this.expired = new Set();
    this.late = [];
    this.events = [];
    this.stderr = "";
    this.stdout = "";
    this.lines = 0;
    this.exited = false;
    children.add(this);
    this.child = spawn(program, args, {cwd: root, stdio: ["pipe", "pipe", "pipe"]});
    this.child.stdout.setEncoding("utf8");
    this.child.stderr.setEncoding("utf8");
    this.child.stdout.on("data", (chunk) => {
      try {
        this.output(chunk);
      } catch (error) {
        this.abort(error);
        suiteController.abort(error);
      }
    });
    this.child.stderr.on("data", (chunk) => {
      this.stderr = `${this.stderr}${chunk}`.slice(-stderrMax);
    });
    this.completion = new Promise((resolveExit) => {
      this.child.once("exit", resolveExit);
      this.child.once("error", (error) => {
        this.abort(error);
        suiteController.abort(error);
        resolveExit();
      });
    });
    this.child.on("exit", (code, signal) => {
      this.exited = true;
      children.delete(this);
      for (const {reject} of this.pending.values())
        reject(Error(`${this.name} exited ${code ?? signal}: ${this.stderr}`));
      this.pending.clear();
    });
  }

  output(chunk) {
    this.stdout += chunk;
    const lines = this.stdout.split("\n");
    this.stdout = lines.pop();
    assert(this.stdout.length <= lineMax, `${this.name} output carry bound`);
    for (const line of lines) {
      if (!line) continue;
      assert(++this.lines <= linesMax && line.length <= lineMax, `${this.name} output bound`);
      const value = JSON.parse(line);
      if (value.event) {
        this.events.push(value);
        continue;
      }
      const pending = this.pending.get(value.id);
      if (!pending && this.expired.delete(value.id)) {
        this.late.push(value);
        continue;
      }
      assert(pending, `${this.name} response without request ${JSON.stringify(value)}`);
      this.pending.delete(value.id);
      if (value.ok) pending.resolve(value);
      else pending.reject(Error(`${this.name}: ${value.error ?? value.err ?? "operation failed"}`));
    }
  }

  command(op, value = {}, timeout = 10000) {
    assert(!this.exited && this.pending.size < pendingMax);
    const id = this.nextId++;
    const request = JSON.stringify({id, op, ...value});
    assert(request.length <= lineMax);
    return new Promise((resolveCommand, reject) => {
      const abort = () => {
        this.pending.delete(id);
        clearTimeout(timer);
        suiteSignal.removeEventListener("abort", abort);
        reject(Error(`${this.name} ${op} aborted`));
      };
      const timer = setTimeout(() => {
        this.pending.delete(id);
        assert(this.expired.size < pendingMax, `${this.name} late response bound`);
        this.expired.add(id);
        suiteSignal.removeEventListener("abort", abort);
        reject(Error(`${this.name} ${op} timeout`));
      }, timeout);
      this.pending.set(id, {
        reject: (error) => {
          clearTimeout(timer);
          suiteSignal.removeEventListener("abort", abort);
          reject(error);
        },
        resolve: (result) => {
          clearTimeout(timer);
          suiteSignal.removeEventListener("abort", abort);
          resolveCommand(result);
        },
      });
      suiteSignal.addEventListener("abort", abort, {once: true});
      this.child.stdin.write(`${request}\n`, (error) => {
        if (error) abort();
      });
    });
  }

  abort(error) {
    for (const {reject} of this.pending.values()) reject(error);
    this.pending.clear();
    if (!this.exited) this.child.kill("SIGKILL");
  }

  async stop() {
    if (this.exited) return;
    void this.command("shutdown", {}, 2000).catch(() => {});
    await Promise.race([this.completion, delay(2000)]);
    if (!this.exited) {
      this.child.kill("SIGTERM");
      await Promise.race([this.completion, delay(1000)]);
    }
    if (!this.exited) this.child.kill("SIGKILL");
    await this.completion;
  }
}

async function waitFor(predicate, timeout = 10000) {
  const end = Date.now() + timeout;
  for (let turns = 0; turns < 400 && Date.now() < end; turns++) {
    if (await predicate()) return;
    await delay(100, undefined, {signal: suiteSignal});
  }
  throw Error("bounded wait timed out");
}

async function verifyExecutable(path) {
  const resolved = resolve(path);
  assert(!relative(root, resolved).startsWith(".."), "binary escapes repository");
  const info = await stat(resolved);
  assert(info.isFile(), "binary is not a regular file");
  await access(resolved, 1);
  return resolved;
}

function assertIds(ids) {
  assert.equal(ids.phase0, "79d62a59d0e47597aeb73cb85ba034c3f67f90e8");
  assert.equal(ids.phase0Other, ids.phase0);
  assert.equal(ids.altair, "e79e947290cd1ce340628caac5541294e6702329");
  assert.equal(ids.invalid, "a4836ac28360e4a1514db96802f612887409b735");
  assert.equal(ids.other, "ece38723d0a2c13e368a1f88a9eb881f68145a30");
}

function quiescent(snapshot) {
  return (
    snapshot.connections === 0 &&
    snapshot.streams === 0 &&
    snapshot.negotiations === 0 &&
    snapshot.gossipPeers === 0 &&
    snapshot.gossipDescriptors === 0 &&
    snapshot.gossipQueuedBytes === 0 &&
    snapshot.heldFrames === 0 &&
    snapshot.meshMembers === 0 &&
    snapshot.pendingValidations === 0 &&
    snapshot.promises === 0 &&
    snapshot.remoteSubscriptions === 0 &&
    snapshot.reqrespInbound === 0 &&
    snapshot.reqrespOutbound === 0 &&
    snapshot.storeEntries === 0 &&
    snapshot.storePages === 0 &&
    snapshot.txRetains === 0
  );
}

async function reclaim(zig, deadline) {
  for (let heartbeat = 0; heartbeat < 6; heartbeat++) {
    await zig.command("advance", {ms: 700});
    await zig.command("pump", {turns: 8});
  }
  await waitFor(async () => quiescent(await zig.command("snapshot")), Math.max(1, deadline - Date.now()));
}

async function exercise(version, binary, zigDials = false) {
  const zig = new Child("zig", binary, []);
  const js = new Child("js", process.execPath, ["--max-old-space-size=256", "test/interop/libp2p_peer.mjs", version]);
  const expectedMessages = [];
  async function delivered(child, size, seed) {
    const expected = summary(payload(size, seed));
    expectedMessages.push({child, expected});
    await waitFor(
      () => child.events.filter((event) => event.event === "message" && event.sha256 === expected.sha256).length === 1,
      30000
    );
    const message = child.events.find((event) => event.event === "message" && event.sha256 === expected.sha256);
    assert.equal(message.length, size);
  }
  try {
    const [zigListen, jsListen, zigIds, jsIds] = await Promise.all([
      zig.command("listen"),
      js.command("listen"),
      zig.command("ids"),
      js.command("ids"),
    ]);
    assertIds(zigIds);
    assertIds(jsIds);
    if (zigDials) {
      await zig.command("dial", {address: jsListen.address});
      await waitFor(async () => (await js.command("snapshot")).connections === 1);
    } else {
      await js.command("dial", {address: zigListen.address});
      await waitFor(async () => (await zig.command("snapshot")).connections === 1);
    }
    const jsPing = await js.command("request", {address: zigListen.address});
    assert.deepEqual({length: jsPing.length, sha256: jsPing.sha256}, summary(Buffer.from([1, 0, 0, 0, 0, 0, 0, 0])));
    await zig.command("request");
    await waitFor(() => zig.events.some((event) => event.event === "chunk" && event.length === 8));
    const zigPing = zig.events.find((event) => event.event === "chunk" && event.length === 8);
    assert.equal(zigPing.sha256, jsPing.sha256);
    if (version === "v12") {
      let jsLarge;
      try {
        jsLarge = await js.command("request", {address: zigListen.address, large: true}, 30000);
      } catch (error) {
        throw Error(
          `js large request ${String(error)} ${JSON.stringify({jsEvents: js.events.slice(-8), zigEvents: zig.events.slice(-8), zigStderr: zig.stderr})}`
        );
      }
      assert.deepEqual({length: jsLarge.length, sha256: jsLarge.sha256}, summary(payload(MAX)));
      assert.equal(jsLarge.context, "01000000");
      await zig.command("request", {large: true}, 30000);
      await waitFor(() => zig.events.some((event) => event.event === "chunk" && event.length === MAX), 30000);
      const large = zig.events.find((event) => event.event === "chunk" && event.length === MAX);
      assert.equal(large.sha256, jsLarge.sha256);
      assert.equal(large.context, "01000000");
      await waitFor(() => zig.events.filter((event) => event.event === "done").length === 2);
    }
    await Promise.all([zig.command("subscribe", {topic: TOPIC}), js.command("subscribe", {topic: TOPIC})]);
    await js.command("publish", {seed: 0x6d2b79f5, size: 65537, topic: TOPIC});
    await delivered(zig, 65537, 0x6d2b79f5);
    await waitFor(async () => (await zig.command("snapshot")).remoteSubscriptions > 0);
    await waitFor(async () => (await zig.command("snapshot")).meshMembers > 0);
    const selected = await zig.command("snapshot");
    assert.equal(selected.connections, 1);
    assert.equal(selected.inboundVersion, version === "v11" ? "v1_1" : "v1_2");
    assert.equal(selected.outboundVersion, version === "v11" ? "v1_1" : "v1_2");
    assert.equal(new Set(zig.events.filter((event) => event.event === "connected").map((event) => event.peer)).size, 1);
    const zigPublish = await zig.command("publish", {seed: 0x6d2b79f7, size: 65537, topic: TOPIC});
    assert(zigPublish.queued > 0, "Zig publish had no mesh recipient");
    let zigAfterPublish;
    let jsAfterPublish;
    try {
      await waitFor(async () => {
        zigAfterPublish = await zig.command("snapshot");
        jsAfterPublish = await js.command("snapshot");
        return js.events.some((event) => event.event === "message" && event.length === 65537);
      }, 10000);
    } catch {
      throw Error(`zig to js gossip timeout ${JSON.stringify({jsAfterPublish, zigAfterPublish})}`);
    }
    await delivered(js, 65537, 0x6d2b79f7);
    for (const [size, seed] of [
      [32 * 1024 + 1, 0x6d2b7a01],
      [2 * 1024 * 1024 + 1, 0x6d2b7a02],
    ]) {
      await js.command("publish", {seed, size, topic: TOPIC});
      await delivered(zig, size, seed);
      const published = await zig.command("publish", {seed: seed + 2, size, topic: TOPIC});
      assert(published.queued > 0, `Zig ${size} gossip had no mesh recipient`);
      await delivered(js, size, seed + 2);
    }
    if (version === "v12") {
      await js.command("rawPublish", {address: zigListen.address, seed: 0x6d2b7a03, size: MAX}, 30000);
      await delivered(zig, MAX, 0x6d2b7a03);
      const published = await zig.command("publish", {seed: 0x6d2b7a04, size: MAX, topic: TOPIC}, 30000);
      assert(published.queued > 0, "Zig exact gossip had no mesh recipient");
      await delivered(js, MAX, 0x6d2b7a04);
    }
    await assert.rejects(zig.command("publish", {size: MAX + 1}), /MessageTooLarge/);
    await assert.rejects(js.command("publish", {size: MAX + 1}), /false|assert/i);
    if (version === "v12") {
      const reconnectDeadline = Date.now() + 30000;
      for (let cycle = 0; cycle < 8; cycle++) {
        const closed = await js.command("disconnect");
        assert.equal(closed.connections, 0, `reconnect ${cycle} disconnect retained JS connection`);
        await waitFor(
          async () => (await js.command("snapshot")).connections === 0,
          Math.max(1, reconnectDeadline - Date.now())
        );
        await reclaim(zig, reconnectDeadline);
        const redial = await js.command("dial", {address: zigListen.address});
        assert.equal(redial.connections, 1, `reconnect ${cycle} did not retain JS connection`);
        try {
          await waitFor(
            async () => (await zig.command("snapshot")).connections === 1,
            Math.max(1, reconnectDeadline - Date.now())
          );
        } catch (error) {
          throw Error(
            `reconnect ${cycle} ${String(error)} ${JSON.stringify({js: await js.command("snapshot"), redial, zig: await zig.command("snapshot"), zigEvents: zig.events.slice(-12)})}`
          );
        }
        let ping;
        try {
          ping = await js.command("request", {address: zigListen.address});
        } catch (error) {
          throw Error(
            `reconnect ${cycle} ping ${String(error)} ${JSON.stringify({jsEvents: js.events.slice(-8), jsLate: js.late.slice(-4), zigEvents: zig.events.slice(-12)})}`
          );
        }
        assert.equal(ping.length, 8);
        await waitFor(
          async () => {
            const current = await zig.command("snapshot");
            return current.remoteSubscriptions > 0 && current.meshMembers > 0;
          },
          Math.max(1, reconnectDeadline - Date.now())
        );
        const messages = zig.events.filter((event) => event.event === "message").length;
        await js.command("publish", {seed: 0x6d2b7a00 + cycle, size: 8, topic: TOPIC});
        await waitFor(
          () => zig.events.filter((event) => event.event === "message").length === messages + 1,
          Math.max(1, reconnectDeadline - Date.now())
        );
      }
      await js.command("disconnect");
      await reclaim(zig, reconnectDeadline);
    }
    for (const {child, expected} of expectedMessages) {
      assert.equal(
        child.events.filter((event) => event.event === "message" && event.sha256 === expected.sha256).length,
        1
      );
    }
    return {jsListen, jsPing, zigListen};
  } finally {
    await Promise.allSettled([zig.stop(), js.stop()]);
  }
}

const binary = await verifyExecutable(process.argv[2] ?? "zig-out/bin/network_interop_peer");
const raw = await exerciseRaw(Child, waitFor, binary);
if (process.argv[3] === "--raw-only") {
  console.log(JSON.stringify({ok: true, raw}));
} else {
  const v12 = await exercise("v12", binary);
  await exercise("v12", binary, true);
  const v11 = await exercise("v11", binary);
  console.log(JSON.stringify({ok: true, raw, v11: v11.jsPing, v12: v12.jsPing}));
}
