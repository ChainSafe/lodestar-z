import { describe, expect, it } from "vitest";
import bindings from "../src/index.ts";

describe("blst", () => {
  describe("PublicKey", () => {
    it("should deserialize from bytes", () => {
      const pk = bindings.blst.PublicKey.fromBytes(TEST_VECTORS.publicKey.compressed);
      expect(pk).toBeDefined();
    });

    it("should take uncompressed byte arrays", () => {
      expectEqualHex(bindings.blst.PublicKey.fromBytes(TEST_VECTORS.publicKey.uncompressed).toBytes(), TEST_VECTORS.publicKey.uncompressed);
      expectEqualHex(bindings.blst.PublicKey.fromBytes(TEST_VECTORS.publicKey.uncompressed).toBytesCompress(), TEST_VECTORS.publicKey.compressed);
    });
    it("should take compressed byte arrays", () => {
      expectEqualHex(bindings.blst.PublicKey.fromBytes(TEST_VECTORS.publicKey.compressed).toBytes(), TEST_VECTORS.publicKey.uncompressed);
      expectEqualHex(bindings.blst.PublicKey.fromBytes(TEST_VECTORS.publicKey.compressed).toBytesCompress(), TEST_VECTORS.publicKey.compressed);
    });

    describe("argument validation", () => {
      for (const [type, invalid] of invalidInputs) {
        it(`should throw on invalid pkBytes type: ${type}`, () => {
          expect(() => bindings.blst.PublicKey.fromBytes(invalid)).to.throw();
        });
      }
      it("should throw incorrect length pkBytes", () => {
        expect(() => bindings.blst.PublicKey.fromBytes(Buffer.alloc(12, "*"))).to.throw("InvalidPublicKeyLength");
      });
    });

    it("should serialize to bytes", () => {
      const pk = bindings.blst.PublicKey.fromBytes(TEST_VECTORS.publicKey.compressed);
      const bytes = pk.toBytes();
      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes.length).toBe(96);
      expect(Buffer.from(bytes).toString("hex")).toBe(Buffer.from(TEST_VECTORS.publicKey.uncompressed).toString("hex"));
    });

    it("should throw on invalid key", () => {
      expect(() => bindings.blst.PublicKey.fromBytes(sullyUint8Array(TEST_VECTORS.publicKey.compressed))).to.throw("BadEncoding");
    });

    it("should throw on zero key", () => {
      const G1_POINT_AT_INFINITY =
        "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

      expect(() => bindings.blst.PublicKey.fromBytes(Buffer.from(G1_POINT_AT_INFINITY))).to.throw("BadEncoding");
    });
  });

  describe("Signature", () => {
    describe("fromBytes()", () => {
      it("should take uncompressed byte arrays", () => {
        expectEqualHex(bindings.blst.Signature.fromBytes(TEST_VECTORS.signature.uncompressed).toBytes(), TEST_VECTORS.signature.uncompressed);
      });
      it("should take compressed byte arrays", () => {
        expectEqualHex(bindings.blst.Signature.fromBytes(TEST_VECTORS.signature.compressed).toBytes(), TEST_VECTORS.signature.uncompressed);
      });
    });

    it("should serialize to bytes", () => {
      const sig = bindings.blst.Signature.fromBytes(TEST_VECTORS.signature.compressed);
      const bytes = sig.toBytesCompress();
      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes.length).toBe(96);
      expect(Buffer.from(bytes).toString("hex")).toBe(Buffer.from(TEST_VECTORS.signature.compressed).toString("hex"));
    });

    describe("argument validation", () => {
      for (const [type, invalid] of invalidInputs) {
        it(`should throw on invalid pkBytes type: ${type}`, () => {
          expect(() => bindings.blst.Signature.fromBytes(invalid)).to.throw();
        });
      }
    });

    it("should throw on invalid length", () => {
      expect(() => bindings.blst.Signature.fromBytes(new Uint8Array(95))).toThrow();
    });
  });

  describe("verify", () => {
    it("should verify valid signature", () => {
      const pk = bindings.blst.PublicKey.fromBytes(TEST_VECTORS.publicKey.compressed);
      const sig = bindings.blst.Signature.fromBytes(TEST_VECTORS.signature.compressed);
      const result = bindings.blst.verify(TEST_VECTORS.message, pk, sig);
      expect(result).toBe(true);
    });

    it("should reject wrong message", () => {
      const pk = bindings.blst.PublicKey.fromBytes(TEST_VECTORS.publicKey.compressed);
      const sig = bindings.blst.Signature.fromBytes(TEST_VECTORS.signature.compressed);
      const wrongMessage = new Uint8Array(32).fill(0);
      const result = bindings.blst.verify(wrongMessage, pk, sig);
      expect(result).toBe(false);
    });
  });

  describe("fastAggregateVerify", () => {
    it("should verify with single pubkey", () => {
      const pk = bindings.blst.PublicKey.fromBytes(TEST_VECTORS.publicKey.compressed);
      const sig = bindings.blst.Signature.fromBytes(TEST_VECTORS.signature.compressed);
      const result = bindings.blst.fastAggregateVerify(TEST_VECTORS.message, [pk], sig);
      expect(result).toBe(true);
    });

    it("should return false for empty pubkeys", () => {
      const sig = bindings.blst.Signature.fromBytes(TEST_VECTORS.signature.compressed);
      const result = bindings.blst.fastAggregateVerify(TEST_VECTORS.message, [], sig);
      expect(result).toBe(false);
    });

    it("should reject wrong message", () => {
      const pk = bindings.blst.PublicKey.fromBytes(TEST_VECTORS.publicKey.compressed);
      const sig = bindings.blst.Signature.fromBytes(TEST_VECTORS.signature.compressed);
      const wrongMessage = new Uint8Array(32).fill(0);
      const result = bindings.blst.fastAggregateVerify(wrongMessage, [pk], sig);
      expect(result).toBe(false);
    });

    it("should throw on wrong message length", () => {
      const pk = bindings.blst.PublicKey.fromBytes(TEST_VECTORS.publicKey.compressed);
      const sig = bindings.blst.Signature.fromBytes(TEST_VECTORS.signature.compressed);
      expect(() => bindings.blst.fastAggregateVerify(new Uint8Array(31), [pk], sig)).toThrow();
    });
  });
});

function fromHex(hexString: string): Uint8Array {
  if (hexString.startsWith("0x")) hexString = hexString.slice(2);
  return Uint8Array.from(Buffer.from(hexString, "hex"));
}

// Test vectors generated with @chainsafe/blst using seed Buffer.alloc(32, "*")
const TEST_VECTORS = {
  message: Uint8Array.from(Buffer.from("lodestarlodestarlodestarlodestar")),
  publicKey: {
    uncompressed: fromHex(
      "0ae7e5822ba97ab07877ea318e747499da648b27302414f9d0b9bb7e3646d248be90c9fdaddfdb93485a6e9334f0109301f36856007e1bc875ab1b00dbf47f9ead16c5562d889d8b270002ade81e78d473204fcb51ede8659bce3d95c67903bc"
    ),
    compressed: fromHex(
      "8ae7e5822ba97ab07877ea318e747499da648b27302414f9d0b9bb7e3646d248be90c9fdaddfdb93485a6e9334f01093"
    ),
  },
  signature: {
    uncompressed: fromHex(
      "01faa68cb2d12b67c54a5a8ac52a7f351f187e4a4f446296c46d56b961159d52ad34a3015cff5753743c1ac2ec7ddbb708dc18431e8b9a53738a5fd08db1981711ae7f6669b9f0486c20546e3bd9e7a1d6cf239563a4b4ffbe0f572086c735aa0aa269bc3fccc963c752b96499f0ba79750ca53eb90a0feb116387b59e40baa427f75bea3094ae9123d35cd543db9e1d07a95a35d5f7371f7315306603c41c473b8bf3af1a812c5ee121cfcdb73536ad28631ded94f86e97684f5f8a0bbd0a3d"
    ),
    compressed: fromHex(
      "81faa68cb2d12b67c54a5a8ac52a7f351f187e4a4f446296c46d56b961159d52ad34a3015cff5753743c1ac2ec7ddbb708dc18431e8b9a53738a5fd08db1981711ae7f6669b9f0486c20546e3bd9e7a1d6cf239563a4b4ffbe0f572086c735aa"
    ),
  },
};

const invalidInputs: [string, any][] = [
  ["boolean", true],
  ["number", 2],
  ["bigint", BigInt("2")],
  ["symbol", Symbol("foo")],
  ["null", null],
  ["undefined", undefined],
  ["object", { foo: "bar" }],
  ["proxy", new Proxy({ foo: "bar" }, {})],
  ["date", new Date("1982-03-24T16:00:00-06:00")],
  [
    "function",
    function() {
      /* no-op */
    },
  ],
  ["NaN", NaN],
  ["promise", Promise.resolve()],
  ["Uint16Array", new Uint16Array()],
  ["Uint32Array", new Uint32Array()],
  ["Map", new Map()],
  ["Set", new Set()],
];

function sullyUint8Array(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(
    Buffer.from([...Uint8Array.prototype.slice.call(bytes, 8), ...Buffer.from("0123456789abcdef", "hex")])
  );
}

function expectEqualHex(value: Uint8Array, expected: Uint8Array): void {
  expect(Buffer.from(value).toString("hex")).to.equal(Buffer.from(expected).toString("hex"));
}



