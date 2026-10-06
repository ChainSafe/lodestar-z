import {applicationConfig, localIntent, startRuntime} from "../utils/network.js";

const config = applicationConfig();
const runtime = startRuntime(config);
await runtime.applyIntent(localIntent(config), config.initialSlot);
console.log("application-ready-exit");
