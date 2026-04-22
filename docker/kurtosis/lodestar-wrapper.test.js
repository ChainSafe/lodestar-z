import test from 'node:test';
import assert from 'node:assert/strict';

import {translateEthereumPackageArgs} from './lodestar-wrapper.js';

test('translates the observed ethereum-package lodestar beacon command into Lodestar-Z argv', () => {
  const raw = [
    'beacon',
    '--logLevel=debug',
    '--port=9000',
    '--discoveryPort=9000',
    '--dataDir=/data/lodestar/beacon-data',
    '--chain.persistInvalidSszObjects=true',
    '--eth1.depositContractDeployBlock=0',
    '--network.connectToDiscv5Bootnodes=true',
    '--discv5=true',
    '--eth1=true',
    '--eth1.providerUrls=http://el-1-reth-lodestar:8545',
    '--execution.urls=http://el-1-reth-lodestar:8551',
    '--rest=true',
    '--rest.address=0.0.0.0',
    '--rest.namespace=*',
    '--rest.port=4000',
    '--nat=true',
    '--jwt-secret=/jwt/jwtsecret',
    '--enr.ip=172.16.0.10',
    '--enr.tcp=9000',
    '--enr.udp=9000',
    '--metrics',
    '--metrics.address=0.0.0.0',
    '--metrics.port=8008',
    '--supernode',
    '--paramsFile=/network-configs/config.yaml',
    '--genesisStateFile=/network-configs/genesis.ssz',
    '--sync.isSingleNode',
    '--network.allowPublishToZeroPeers',
  ];

  assert.deepStrictEqual(translateEthereumPackageArgs(raw), [
    'beacon',
    '--logLevel', 'debug',
    '--port', '9000',
    '--discoveryPort', '9000',
    '--dataDir', '/data/lodestar/beacon-data',
    '--discv5',
    '--execution.urls', 'http://el-1-reth-lodestar:8551',
    '--rest',
    '--rest.address', '0.0.0.0',
    '--rest.port', '4000',
    '--nat',
    '--jwt-secret', '/jwt/jwtsecret',
    '--enr.ip', '172.16.0.10',
    '--enr.tcp', '9000',
    '--enr.udp', '9000',
    '--metrics',
    '--metrics.address', '0.0.0.0',
    '--metrics.port', '8008',
    '--supernode',
    '--paramsFile', '/network-configs/config.yaml',
    '--checkpointState', '/network-configs/genesis.ssz',
    '--sync.isSingleNode',
    '--network.allowPublishToZeroPeers',
  ]);
});

test('translates the observed ethereum-package lodestar validator command into Lodestar-Z argv', () => {
  const raw = [
    'validator',
    '--logLevel=debug',
    '--paramsFile=/network-configs/config.yaml',
    '--beaconNodes=http://cl-1-lodestar-reth:4000',
    '--suggestedFeeRecipient=0x8943545177806ED17B9F23F0a21ee5948eCaa776',
    '--metrics',
    '--metrics.address=0.0.0.0',
    '--metrics.port=8080',
    '--graffiti=1-reth-lodestar',
    '--useProduceBlockV3',
    '--disableKeystoresThreadPool',
    '--keystoresDir=/validator-keys/keys',
    '--secretsDir=/validator-keys/secrets',
  ];

  assert.deepStrictEqual(translateEthereumPackageArgs(raw), [
    'validator',
    '--logLevel', 'debug',
    '--paramsFile', '/network-configs/config.yaml',
    '--beaconNodes', 'http://cl-1-lodestar-reth:4000',
    '--suggestedFeeRecipient', '0x8943545177806ED17B9F23F0a21ee5948eCaa776',
    '--metrics',
    '--metrics.address', '0.0.0.0',
    '--metrics.port', '8080',
    '--graffiti', '1-reth-lodestar',
    '--disableKeystoresThreadPool',
    '--keystoresDir', '/validator-keys/keys',
    '--secretsDir', '/validator-keys/secrets',
  ]);
});

test('drops false-valued booleans instead of passing them through', () => {
  assert.deepStrictEqual(
    translateEthereumPackageArgs([
      'beacon',
      '--rest=false',
      '--metrics=false',
      '--nat=false',
      '--supernode=false',
    ]),
    ['beacon'],
  );
});

test('passes through help for the beacon subcommand', () => {
  assert.deepStrictEqual(translateEthereumPackageArgs(['beacon', '--help']), ['beacon', '--help']);
});

test('passes through help for the validator subcommand', () => {
  assert.deepStrictEqual(translateEthereumPackageArgs(['validator', '--help']), ['validator', '--help']);
});

test('fails fast on unhandled ethereum-package arguments', () => {
  assert.throws(
    () => translateEthereumPackageArgs(['beacon', '--totally-unknown=true']),
    /Unhandled ethereum-package arg: --totally-unknown/,
  );
});
