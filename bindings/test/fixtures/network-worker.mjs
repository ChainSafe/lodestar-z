import {parentPort} from "node:worker_threads";
import {createNativeNetworkRuntime} from "../../src/network.js";
import {networkConfig} from "../utils/network.ts";
const runtime = createNativeNetworkRuntime(networkConfig(), () => undefined);
const identity = await runtime.ready;
parentPort.postMessage(identity.localEndpoint.port);
parentPort.on("message", () => undefined);
