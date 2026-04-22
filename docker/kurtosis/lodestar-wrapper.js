import {spawn} from 'node:child_process';
import {pathToFileURL} from 'node:url';

const commonValueFlags = new Map([
  ['--logLevel', '--logLevel'],
  ['--paramsFile', '--paramsFile'],
]);

const commonBooleanFlags = new Set([
  '--help',
]);

const commandConfigs = {
  beacon: {
    passthroughValueFlags: new Map([
      ...commonValueFlags,
      ['--port', '--port'],
      ['--discoveryPort', '--discoveryPort'],
      ['--dataDir', '--dataDir'],
      ['--execution.urls', '--execution.urls'],
      ['--rest.address', '--rest.address'],
      ['--rest.port', '--rest.port'],
      ['--jwt-secret', '--jwt-secret'],
      ['--enr.ip', '--enr.ip'],
      ['--enr.tcp', '--enr.tcp'],
      ['--enr.udp', '--enr.udp'],
      ['--metrics.address', '--metrics.address'],
      ['--metrics.port', '--metrics.port'],
    ]),
    translatedValueFlags: new Map([
      ['--genesisStateFile', '--checkpointState'],
    ]),
    passthroughBooleanFlags: new Set([
      ...commonBooleanFlags,
      '--discv5',
      '--rest',
      '--nat',
      '--metrics',
      '--supernode',
      '--sync.isSingleNode',
      '--network.allowPublishToZeroPeers',
    ]),
    ignoredFlags: new Set([
      '--chain.persistInvalidSszObjects',
      '--eth1.depositContractDeployBlock',
      '--network.connectToDiscv5Bootnodes',
      '--eth1',
      '--eth1.providerUrls',
      '--rest.namespace',
    ]),
  },
  validator: {
    passthroughValueFlags: new Map([
      ...commonValueFlags,
      ['--beaconNodes', '--beaconNodes'],
      ['--suggestedFeeRecipient', '--suggestedFeeRecipient'],
      ['--metrics.address', '--metrics.address'],
      ['--metrics.port', '--metrics.port'],
      ['--graffiti', '--graffiti'],
      ['--keystoresDir', '--keystoresDir'],
      ['--secretsDir', '--secretsDir'],
    ]),
    translatedValueFlags: new Map(),
    passthroughBooleanFlags: new Set([
      ...commonBooleanFlags,
      '--metrics',
      '--disableKeystoresThreadPool',
    ]),
    ignoredFlags: new Set([
      '--useProduceBlockV3',
    ]),
  },
};

function splitOptionToken(token) {
  if (!token.startsWith('--')) return {name: token, value: null, inline: false};
  const eqIndex = token.indexOf('=');
  if (eqIndex === -1) return {name: token, value: null, inline: false};
  return {
    name: token.slice(0, eqIndex),
    value: token.slice(eqIndex + 1),
    inline: true,
  };
}

function isExplicitFalse(value) {
  return value === 'false';
}

function isExplicitTrue(value) {
  return value === 'true';
}

function requireValue(flag, value) {
  if (value == null || value === '') {
    throw new Error(`Missing value for ${flag}`);
  }
  return value;
}

export function translateEthereumPackageArgs(rawArgs) {
  if (rawArgs.length === 0) {
    throw new Error('Expected ethereum-package to provide a subcommand');
  }

  const subcommand = rawArgs[0];
  const config = commandConfigs[subcommand];
  if (!config) {
    throw new Error(`Expected ethereum-package subcommand "beacon" or "validator", got: ${subcommand}`);
  }

  const translated = [subcommand];

  for (let i = 1; i < rawArgs.length; i += 1) {
    const token = rawArgs[i];
    const {name, value: inlineValue, inline} = splitOptionToken(token);

    if (!name.startsWith('--')) {
      translated.push(token);
      continue;
    }

    if (config.ignoredFlags.has(name)) {
      if (!inline && rawArgs[i + 1] && !rawArgs[i + 1].startsWith('--')) {
        i += 1;
      }
      continue;
    }

    if (config.passthroughBooleanFlags.has(name)) {
      if (inline) {
        if (isExplicitFalse(inlineValue)) continue;
        if (!isExplicitTrue(inlineValue)) {
          throw new Error(`Boolean flag ${name} must be true/false when provided with '='`);
        }
      }
      translated.push(name);
      continue;
    }

    const translatedValueFlag = config.translatedValueFlags.get(name) ?? config.passthroughValueFlags.get(name);
    if (translatedValueFlag) {
      let value = inlineValue;
      if (!inline) {
        value = rawArgs[i + 1] ?? null;
        i += 1;
      }
      translated.push(translatedValueFlag, requireValue(name, value));
      continue;
    }

    throw new Error(`Unhandled ethereum-package arg: ${name}`);
  }

  return translated;
}

export function runWrapper(rawArgs, options = {}) {
  const binary = options.binary ?? process.env.LODESTAR_Z_BINARY ?? '/usr/local/bin/lodestar-z';
  const translated = translateEthereumPackageArgs(rawArgs);

  console.error(`[lodestar-z-kurtosis-wrapper] raw argv: ${JSON.stringify(rawArgs)}`);
  console.error(`[lodestar-z-kurtosis-wrapper] translated argv: ${JSON.stringify(translated)}`);

  if (options.dryRun ?? process.env.LODESTAR_Z_WRAPPER_DRY_RUN === '1') {
    return {binary, translated, child: null};
  }

  const child = spawn(binary, translated, {stdio: 'inherit'});
  child.on('error', (error) => {
    console.error(`[lodestar-z-kurtosis-wrapper] failed to spawn ${binary}: ${error.message}`);
    process.exit(1);
  });
  child.on('exit', (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code ?? 1);
  });

  return {binary, translated, child};
}

function isMainModule() {
  return process.argv[1] != null && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMainModule()) {
  runWrapper(process.argv.slice(2));
}
