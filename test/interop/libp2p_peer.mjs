import assert from "node:assert/strict";
import {createInterface} from "node:readline";
import {quic} from "@chainsafe/libp2p-quic";
import {privateKeyFromRaw} from "@libp2p/crypto/keys";
import {StrictNoSign, gossipsub} from "@libp2p/gossipsub";
import {identify} from "@libp2p/identify";
import {multiaddr} from "@multiformats/multiaddr";
import {createLibp2p} from "libp2p";
import {compressSync, uncompressSync} from "snappy";
import {
  BLOCKS,
  MAX,
  PING,
  RPC_MAX,
  TOPIC,
  encodePayload,
  loopback,
  messageId,
  payload,
  readPayload,
  sendFragments,
  summary,
} from "./codec.mjs";

const lineMax = 65536;
const commandMax = 1024;
const pendingMax = 32;
const eventMax = 1024;
const version = process.argv[2] === "v11" ? "v11" : "v12";
const protocols = version === "v11" ? ["/meshsub/1.1.0"] : ["/meshsub/1.2.0", "/meshsub/1.1.0"];
const phase0 = new Set([TOPIC]);
const messages = [];
let node;
let commands = 0;
let active = 0;

function emit(value) {
  const text = JSON.stringify(value);
  assert(text.length <= lineMax, "output bound");
  process.stdout.write(`${text}\n`);
}

function idFor(message) {
  return messageId(message.topic, message.data, true, phase0.has(message.topic));
}

function validCommand(value) {
  assert(value && typeof value === "object" && !Array.isArray(value));
  assert(Number.isInteger(value.id) && value.id > 0 && value.id <= 0x7fffffff);
  assert(typeof value.op === "string" && value.op.length > 0 && value.op.length <= 32);
  return value;
}

async function* chunks(stream) {
  let count = 0;
  let bytes = 0;
  for await (const part of stream) {
    const value = part.subarray();
    count += 1;
    bytes += value.length;
    assert(count <= 32768 && bytes <= RPC_MAX + 32, "stream bound");
    yield value;
  }
}

async function respond(stream) {
  const request = await readPayload(chunks(stream));
  const isPing = request.bytes.length === 8;
  assert(isPing || request.bytes.length === 24, "request shape");
  const response = isPing ? Buffer.from([1, 0, 0, 0, 0, 0, 0, 0]) : payload(MAX, 0x6d2b79f5);
  const header = isPing ? Buffer.from([0]) : Buffer.from([0, 1, 0, 0, 0]);
  await sendFragments(stream, Buffer.concat([header, encodePayload(response, false)]), AbortSignal.timeout(30000));
  await stream.close({signal: AbortSignal.timeout(30000)});
}

async function createPeer() {
  const secret = Buffer.alloc(32);
  secret[31] = version === "v11" ? 42 : 41;
  node = await createLibp2p({
    addresses: {listen: ["/ip4/127.0.0.1/udp/0/quic-v1"]},
    connectionGater: {denyDialMultiaddr: async (address) => !address.toString().startsWith("/ip4/127.0.0.1/")},
    privateKey: privateKeyFromRaw(secret),
    services: {
      identify: identify(),
      pubsub: (components) => {
        const service = gossipsub({
          D: 8,
          // biome-ignore lint/style/useNamingConvention: js-libp2p publishes this option spelling.
          Dhi: 12,
          // biome-ignore lint/style/useNamingConvention: js-libp2p publishes this option spelling.
          Dlazy: 6,
          // biome-ignore lint/style/useNamingConvention: js-libp2p publishes this option spelling.
          Dlo: 6,
          dataTransform: {
            inboundTransform: (_topic, data) => uncompressSync(data),
            outboundTransform: (_topic, data) => compressSync(data),
          },
          floodPublish: false,
          globalSignaturePolicy: StrictNoSign,
          heartbeatInterval: 700,
          maxInboundDataLength: RPC_MAX,
          maxOutboundBufferSize: RPC_MAX + 10,
          mcacheGossip: 3,
          mcacheLength: 6,
          msgIdFn: idFor,
        })(components);
        service.protocols = [...protocols];
        return service;
      },
    },
    start: false,
    transports: [quic()],
  });
  await node.handle([PING, BLOCKS], respond, {maxInboundStreams: 8});
  node.services.pubsub.addEventListener("message", (event) => {
    if (messages.length < eventMax) {
      const value = {
        messageId: Buffer.from(event.detail.msgId).toString("hex"),
        topic: event.detail.topic,
        ...summary(event.detail.data),
      };
      messages.push(value);
      emit({event: "message", ...value});
    }
  });
  await node.start();
  assert.deepEqual(
    node
      .getProtocols()
      .filter((item) => item.startsWith("/meshsub/"))
      .sort(),
    [...protocols].sort()
  );
}

async function request(address, large) {
  const signal = AbortSignal.timeout(large ? 30000 : 10000);
  const stream = await node.dialProtocol(multiaddr(loopback(address)), large ? BLOCKS : PING, {signal});
  const result = readPayload(chunks(stream), true, large);
  const bytes = large
    ? Buffer.from([0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    : Buffer.from([1, 0, 0, 0, 0, 0, 0, 0]);
  await sendFragments(stream, encodePayload(bytes, false), signal);
  await stream.close({signal});
  const decoded = await result;
  assert.equal(decoded.result, 0);
  return {...summary(decoded.bytes), context: decoded.context};
}

async function execute(command) {
  switch (command.op) {
    case "listen":
      return {address: loopback(node.getMultiaddrs()[0].toString()), protocols};
    case "dial":
      loopback(command.address);
      await node.dial(multiaddr(command.address), {signal: AbortSignal.timeout(10000)});
      return {connections: node.getConnections().length};
    case "subscribe":
      node.services.pubsub.subscribe(command.topic ?? TOPIC);
      return {subscribers: node.services.pubsub.getSubscribers(command.topic ?? TOPIC).length};
    case "publish": {
      const size = command.size ?? 65537;
      assert(Number.isInteger(size) && size >= 0 && size <= MAX);
      node.services.pubsub.publish(command.topic ?? TOPIC, payload(size, command.seed ?? 0x6d2b79f5));
      return {size};
    }
    case "request":
      return request(command.address, command.large === true);
    case "snapshot":
      return {
        connections: node.getConnections().length,
        messages: messages.length,
        protocols,
        subscribers: node.services.pubsub.getSubscribers(command.topic ?? TOPIC).length,
      };
    case "disconnect":
      await Promise.allSettled(node.getConnections().map((connection) => connection.close()));
      return {connections: node.getConnections().length};
    case "ids":
      return {
        altair: messageId(TOPIC, Buffer.from("hello")).toString("hex"),
        invalid: messageId(TOPIC, Buffer.from([255]), false).toString("hex"),
        other: messageId(TOPIC.replace("beacon_block", "voluntary_exit"), Buffer.from("hello")).toString("hex"),
        phase0: messageId(TOPIC, Buffer.from("hello"), true, true).toString("hex"),
      };
    case "shutdown":
      await node.stop();
      return {shutdown: true};
    default:
      throw Error("unknown operation");
  }
}

await createPeer();
const input = createInterface({crlfDelay: Infinity, input: process.stdin});
for await (const line of input) {
  if (line.length > lineMax || ++commands > commandMax) break;
  let command;
  try {
    command = validCommand(JSON.parse(line));
    assert(++active <= pendingMax, "pending bound");
    const result = await execute(command);
    emit({id: command.id, ok: true, ...result});
    active -= 1;
    if (command.op === "shutdown") break;
  } catch (error) {
    active = Math.max(0, active - 1);
    emit({error: error instanceof Error ? error.message : "invalid command", id: command?.id ?? 0, ok: false});
  }
}
if (node?.status === "started") await node.stop();
