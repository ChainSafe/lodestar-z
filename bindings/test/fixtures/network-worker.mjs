import {parentPort} from "node:worker_threads";
import {createNativeNetworkApplicationRuntime} from "../../src/network.js";
import {applicationConfig} from "../utils/network.ts";
const runtime = createNativeNetworkApplicationRuntime(applicationConfig(), () => undefined);
const identity = await runtime.ready;
parentPort.postMessage(identity.localEndpoint.port);
parentPort.on("message", () => undefined);
