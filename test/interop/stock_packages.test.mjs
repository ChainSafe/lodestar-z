import assert from "node:assert/strict";
import {test} from "node:test";
import {Child} from "./child.mjs";
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
    } finally {
      await peer.stop();
    }
  });
}
