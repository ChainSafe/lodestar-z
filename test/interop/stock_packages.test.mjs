import assert from "node:assert/strict";
import {test} from "node:test";
import {quic} from "@chainsafe/libp2p-quic";
import {multiaddr} from "@multiformats/multiaddr";
import {createLibp2p} from "libp2p";
import {Child} from "./child.mjs";
import {encodePayload, readPayload, sendFragments} from "./codec.mjs";
import {stockPackages} from "./stock_packages.mjs";

test("installed stock fixture resolves pinned peers and the Lodestar response decoder", async () => {
  const packages = stockPackages("installed");
  assert.equal(await packages.version("@lodestar/reqresp"), "1.46.0");
  assert.equal(await packages.version("libp2p"), "3.3.10");
  for (const [name, exported] of [
    ["libp2p", "createLibp2p"],
    ["@chainsafe/libp2p-quic", "quic"],
    ["@libp2p/crypto/keys", "privateKeyFromRaw"],
    ["@libp2p/identify", "identify"],
    ["@libp2p/gossipsub", "gossipsub"],
    ["@multiformats/multiaddr", "multiaddr"],
    ["snappy", "compressSync"],
  ]) {
    assert.equal(typeof (await packages.load(name))[exported], "function", `${name} ${exported}`);
  }
  assert.equal(typeof (await packages.responseDecoder()).responseDecode, "function");
});

for (const mode of ["", "gossip"]) {
  test(`installed stock fixture starts and stops its ${mode || "request"} responder`, async () => {
    const peer = new Child(`stock-${mode || "request"}`, process.execPath, [
      "test/interop/request_responder.mjs",
      "installed",
      "",
      mode,
    ]);
    try {
      const ready = await peer.command("ready");
      assert.deepEqual(ready.versions, {libp2p: "3.3.10", quic: "2.1.3"});
      assert(ready.protocols.includes("/meshsub/1.2.0"), "ordinary managed peers must support gossip");
      const client = await createLibp2p({transports: [quic()]});
      try {
        for (const [method, length] of [
          ["metadata/2", 17],
          ["metadata/3", 25],
          ["ping/1", 8],
        ]) {
          const signal = AbortSignal.timeout(5000);
          const stream = await client.dialProtocol(
            multiaddr(ready.address),
            `/eth2/beacon_chain/req/${method}/ssz_snappy`,
            {signal}
          );
          const abort = () => stream.abort(signal.reason);
          signal.addEventListener("abort", abort, {once: true});
          try {
            if (method === "ping/1") {
              const request = Buffer.alloc(8);
              request.writeBigUInt64LE(99n);
              await sendFragments(stream, encodePayload(request), signal);
            }
            await stream.close({signal});
            const response = await readPayload(stream, true);
            const expected = Buffer.alloc(length);
            expected.writeBigUInt64LE(1n);
            if (method === "metadata/3") expected.writeBigUInt64LE(1n, 17);
            assert.equal(response.result, 0);
            assert.deepEqual(response.bytes, expected, method);
          } finally {
            signal.removeEventListener("abort", abort);
            stream.abort(Error("fixture control check finished"));
          }
        }
      } finally {
        await client.stop();
      }
    } finally {
      await peer.stop();
    }
  });
}
