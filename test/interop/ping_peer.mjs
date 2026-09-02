import { quic } from "@chainsafe/libp2p-quic";
import { generateKeyPair } from "@libp2p/crypto/keys";
import { ping } from "@libp2p/ping";
import { multiaddr } from "@multiformats/multiaddr";
import { createLibp2p } from "libp2p";

const mode = process.argv[2];
if (mode !== "listen" && mode !== "dial") {
  console.error("usage: node test/interop/ping_peer.mjs listen | dial <multiaddr>");
  process.exit(2);
}

const node = await createLibp2p({
  privateKey: await generateKeyPair("secp256k1"),
  addresses: { listen: mode === "listen" ? ["/ip4/127.0.0.1/udp/0/quic-v1"] : [] },
  transports: [quic()],
  services: { ping: ping() },
});
await node.start();

if (mode === "listen") {
  for (const address of node.getMultiaddrs()) {
    console.log(address.toString());
  }
  await new Promise(() => {});
} else {
  const rtt = await node.services.ping.ping(multiaddr(process.argv[3]));
  console.log(`ping rtt_ms=${rtt}`);
  await node.stop();
}
