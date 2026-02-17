import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {config} from "@lodestar/config/default";
import * as era from "@lodestar/era";
import {afterAll, beforeAll, describe, expect, it} from "vitest";
import bindings from "../src/index.js";
import {getFirstEraFilePath} from "./eraFiles.ts";

describe("pubkeys", () => {
  let validatorIndex = 0;
  let validatorPubkey: Uint8Array;
  let tempPkixPath = "";

  beforeAll(async () => {
    bindings.pool.ensureCapacity(10_000_000);
    bindings.pubkeys.ensureCapacity(2_000_000);

    const reader = await era.era.EraReader.open(config, getFirstEraFilePath());
    const stateBytes = await reader.readSerializedState();
    const state = bindings.BeaconStateView.createFromBytes(stateBytes);

    validatorIndex = Math.min(1024, state.validatorCount - 1);
    validatorPubkey = state.getValidator(validatorIndex).pubkey;

    tempPkixPath = path.join(os.tmpdir(), `lodestar-z-pubkeys-${process.pid}-${Date.now()}.pkix`);
  }, 120_000);

  afterAll(() => {
    if (tempPkixPath.length > 0) {
      fs.rmSync(tempPkixPath, {force: true});
    }
  });

  it("pubkey2index.get should return validator index for a cached pubkey", () => {
    expect(bindings.pubkeys.pubkey2index.get(validatorPubkey)).toBe(validatorIndex);
  });

  it("index2pubkey.get should return PublicKey for a cached index", () => {
    const cachedPubkey = bindings.pubkeys.index2pubkey.get(validatorIndex);
    expect(cachedPubkey).toBeDefined();
  });

  it("pubkey2index.get should return undefined for unknown pubkey", () => {
    expect(bindings.pubkeys.pubkey2index.get(new Uint8Array(48))).toBeUndefined();
  });

  it("index2pubkey.get should return undefined for out-of-range index", () => {
    expect(bindings.pubkeys.index2pubkey.get(0xffffffff)).toBeUndefined();
  });

  it("pubkey2index.get should throw for invalid pubkey length", () => {
    expect(() => bindings.pubkeys.pubkey2index.get(new Uint8Array(47))).toThrow();
  });

  it("pubkeys.save/load should roundtrip cache contents", () => {
    bindings.pubkeys.save(tempPkixPath);
    bindings.pubkeys.load(tempPkixPath);

    expect(bindings.pubkeys.pubkey2index.get(validatorPubkey)).toBe(validatorIndex);

    const cachedPubkey = bindings.pubkeys.index2pubkey.get(validatorIndex);
    expect(cachedPubkey).toBeDefined();
  });
});
