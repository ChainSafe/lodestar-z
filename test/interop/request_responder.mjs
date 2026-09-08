import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {boundedLines} from "./bounded_lines.mjs";
import {encodePayload, payload, readPayload, sendFragments} from "./codec.mjs";
import {readEmptyRequest} from "./managed_control.mjs";
import {stockPackages} from "./stock_packages.mjs";

const {load, version} = stockPackages(process.argv[2]);
const {createLibp2p} = await load("libp2p");
const {quic} = await load("@chainsafe/libp2p-quic");
const {privateKeyFromRaw} = await load("@libp2p/crypto/keys");
const {identify} = await load("@libp2p/identify");
const {multiaddr} = await load("@multiformats/multiaddr");
const secret = new Uint8Array(32);
secret[31] = 62;
const blockProtocol = "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy";
let scenario = "chunks";
let digest = Buffer.from([1, 2, 3, 4]);
let length = 4000;
let count = 2;
let requests = 0;
let active = 0;
let lastRequest = "";
const held = new Set();
const control = {ping: 0, status: 0};
const node = await createLibp2p({
  addresses: {listen: ["/ip4/127.0.0.1/udp/0/quic-v1"]},
  connectionGater: {denyDialMultiaddr: async (address) => !address.toString().startsWith("/ip4/127.0.0.1/")},
  privateKey: privateKeyFromRaw(secret),
  services: {identify: identify({runOnConnectionOpen: false})},
  start: false,
  transports: [quic()],
});
const status = Buffer.alloc(84);
status.set(digest);
status.writeBigUInt64LE(100n, 76);
async function respondControl(stream) {
  try {
    const protocol = stream.protocol;
    const metadata = protocol.includes("/metadata/");
    if (metadata) await readEmptyRequest(stream);
    const request = metadata ? null : await readPayload(stream);
    let bytes;
    if (protocol.includes("/status/")) {
      control.status++;
      bytes = status;
    } else if (protocol.includes("/ping/")) {
      control.ping++;
      bytes = request.bytes;
    } else if (protocol.includes("/metadata/3/")) {
      bytes = Buffer.alloc(25);
      bytes.writeBigUInt64LE(1n, 17);
    } else if (metadata) bytes = Buffer.alloc(17);
    else bytes = Buffer.alloc(0);
    await sendFragments(stream, Buffer.concat([Buffer.from([0]), encodePayload(bytes)]), AbortSignal.timeout(5000));
    await stream.close({signal: AbortSignal.timeout(5000)});
  } catch (error) {
    stream.abort(error);
  }
}
for (const method of ["status/1", "ping/1", "goodbye/1", "metadata/2", "metadata/3"]) {
  await node.handle(`/eth2/beacon_chain/req/${method}/ssz_snappy`, respondControl, {
    maxInboundStreams: 8,
    maxOutboundStreams: 8,
  });
}
await node.handle(
  blockProtocol,
  async (stream) => {
    active++;
    try {
      assert(active <= 8 && ++requests <= 128);
      const request = await readPayload(stream);
      lastRequest = request.bytes.toString("hex");
      assert(request.bytes.length <= 4096);
      const selected = scenario;
      if (selected === "hold") {
        assert(held.size < 8);
        held.add(stream);
        const timer = setTimeout(() => {
          held.delete(stream);
          stream.abort(Error("fixture hold bound"));
        }, 15000);
        timer.unref();
        stream.addEventListener(
          "close",
          () => {
            clearTimeout(timer);
            held.delete(stream);
          },
          {once: true}
        );
        return;
      }
      if (selected === "peer-error") {
        await sendFragments(
          stream,
          Buffer.concat([Buffer.from([3]), encodePayload(Buffer.from([0, 0xff, 0xc3, 0x28, 0x80]))]),
          AbortSignal.timeout(5000)
        );
      } else if (selected !== "empty") {
        for (let i = 0; i < count; i++) {
          const bytes = selected === "hoodi" ? await readFile(process.argv[3]) : payload(length, 71 + i);
          await sendFragments(
            stream,
            Buffer.concat([Buffer.from([0]), digest, encodePayload(bytes)]),
            AbortSignal.timeout(10000)
          );
        }
      }
      await stream.close({signal: AbortSignal.timeout(5000)});
    } catch (error) {
      stream.abort(error);
    } finally {
      active--;
    }
  },
  {maxInboundStreams: 8, maxOutboundStreams: 8}
);
await node.start();
let commands = 0;
for await (const line of boundedLines(process.stdin)) {
  assert(++commands <= 512);
  const command = JSON.parse(line);
  try {
    let response = {};
    if (command.op === "ready")
      response = {
        address: node.getMultiaddrs()[0].toString(),
        peer: Buffer.from(node.peerId.toMultihash().bytes).toString("hex"),
        versions: {libp2p: await version("libp2p"), quic: await version("@chainsafe/libp2p-quic")},
      };
    else if (command.op === "scenario") {
      assert(["chunks", "empty", "peer-error", "hold", "hoodi"].includes(command.scenario));
      scenario = command.scenario;
      length = command.length ?? 4000;
      count = command.count ?? 2;
      assert(Number.isInteger(length) && length >= 0 && length <= 10 * 1024 * 1024);
      assert(Number.isInteger(count) && count >= 0 && count <= 4);
      digest = Buffer.from(command.digest ?? "01020304", "hex");
      assert.equal(digest.length, 4);
    } else if (command.op === "stats") response = {active, control, lastRequest, requests};
    else if (command.op === "ping") {
      assert(/^\/ip4\/127\.0\.0\.1\/udp\/[0-9]+\/quic-v1\/p2p\/[A-Za-z0-9]+$/.test(command.address));
      const stream = await node.dialProtocol(multiaddr(command.address), "/eth2/beacon_chain/req/ping/1/ssz_snappy", {
        signal: AbortSignal.timeout(5000),
      });
      const ping = Buffer.alloc(8);
      ping.writeBigUInt64LE(1n);
      await sendFragments(stream, encodePayload(ping), AbortSignal.timeout(5000));
      await stream.close({signal: AbortSignal.timeout(5000)});
      const reply = await readPayload(stream, true);
      assert.equal(reply.result, 0);
      response = {length: reply.bytes.length};
    } else if (command.op === "shutdown") {
      for (const stream of held) stream.abort(Error("fixture shutdown"));
      await node.stop();
      process.stdout.write(`${JSON.stringify({id: command.id, ok: true})}\n`);
      break;
    } else throw Error("unknown command");
    process.stdout.write(`${JSON.stringify({id: command.id, ok: true, ...response})}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({error: String(error), id: command.id, ok: false})}\n`);
  }
}
await node.stop();
