# Lodestar TypeScript Peer Manager - Complete Source Reference

Source: https://github.com/ChainSafe/lodestar/tree/unstable/packages/beacon-node/src/network/peers
Branch: `unstable` (fetched 2026-04-02)

---

## Table of Contents

1. [peers/index.ts](#peersindexts)
2. [peers/peerManager.ts](#peerspeerManagerts)
3. [peers/peersData.ts](#peerspeersDatts)
4. [peers/client.ts](#peersclientts)
5. [peers/discover.ts](#peersdiscoverts)
6. [peers/datastore.ts](#peersdatastorets)
7. [peers/score/index.ts](#peersscoreindexts)
8. [peers/score/interface.ts](#peersscoreinterfacets)
9. [peers/score/constants.ts](#peersscoreconstantsts)
10. [peers/score/score.ts](#peersscorescorets)
11. [peers/score/store.ts](#peersscorestorets)
12. [peers/score/utils.ts](#peersscoreutilsts)
13. [peers/utils/index.ts](#peersutilsindexts)
14. [peers/utils/prioritizePeers.ts](#peersutilsprioritizePeersts)
15. [peers/utils/assertPeerRelevance.ts](#peersutilsassertPeerRelevancets)
16. [peers/utils/getConnectedPeerIds.ts](#peersutilsgetConnectedPeerIdsts)
17. [peers/utils/subnetMap.ts](#peersutilssubnetMapts)
18. [peers/utils/enrSubnetsDeserialize.ts](#peersutilsenrSubnetsDeserializets)

---


## peers/index.ts

```typescript
export * from "./peerManager.js";
export * from "./score/index.js";
```

---


## peers/peerManager.ts

```typescript
import {Connection, PeerId, PrivateKey} from "@libp2p/interface";
import {BitArray} from "@chainsafe/ssz";
import {BeaconConfig} from "@lodestar/config";
import {LoggerNode} from "@lodestar/logger/node";
import {ForkSeq, SLOTS_PER_EPOCH, SYNC_COMMITTEE_SUBNET_COUNT} from "@lodestar/params";
import {computeTimeAtSlot} from "@lodestar/state-transition";
import {Metadata, Status, altair, fulu, phase0} from "@lodestar/types";
import {prettyPrintIndices, toHex, withTimeout} from "@lodestar/utils";
import {GOODBYE_KNOWN_CODES, GoodByeReasonCode, Libp2pEvent} from "../../constants/index.js";
import {IClock} from "../../util/clock.js";
import {computeColumnsForCustodyGroup, getCustodyGroups} from "../../util/dataColumns.js";
import {callInNextEventLoop} from "../../util/eventLoop.js";
import {NetworkCoreMetrics} from "../core/metrics.js";
import {LodestarDiscv5Opts} from "../discv5/types.js";
import {INetworkEventBus, NetworkEvent, NetworkEventData} from "../events.js";
import {Eth2Gossipsub} from "../gossip/gossipsub.js";
import {Libp2p} from "../interface.js";
import {SubnetType} from "../metadata.js";
import {NetworkConfig} from "../networkConfig.js";
import {ReqRespMethod} from "../reqresp/ReqRespBeaconNode.js";
import {StatusCache} from "../statusCache.js";
import {NodeId, SubnetsService, computeNodeId} from "../subnets/index.js";
import {getConnection, getConnectionsMap, prettyPrintPeerId, prettyPrintPeerIdStr} from "../util.js";
import {ClientKind, getKnownClientFromAgentVersion} from "./client.js";
import {PeerDiscovery, SubnetDiscvQueryMs} from "./discover.js";
import {PeerData, PeersData} from "./peersData.js";
import {NO_COOL_DOWN_APPLIED} from "./score/constants.js";
import {IPeerRpcScoreStore, PeerAction, PeerScoreStats, ScoreState, updateGossipsubScores} from "./score/index.js";
import {
  assertPeerRelevance,
  getConnectedPeerIds,
  hasSomeConnectedPeer,
  prioritizePeers,
  renderIrrelevantPeerType,
} from "./utils/index.js";

/** heartbeat performs regular updates such as updating reputations and performing discovery requests */
const HEARTBEAT_INTERVAL_MS = 30 * 1000;
/** The time in seconds between PING events. We do not send a ping if the other peer has PING'd us */
const PING_INTERVAL_INBOUND_MS = 15 * 1000; // Offset to not ping when outbound reqs
const PING_INTERVAL_OUTBOUND_MS = 20 * 1000;
/** The time in seconds between re-status's peers. */
const STATUS_INTERVAL_MS = 5 * 60 * 1000;
/** Expect a STATUS request from on inbound peer for some time. Afterwards the node does a request */
const STATUS_INBOUND_GRACE_PERIOD = 15 * 1000;
/** Internal interval to check PING and STATUS timeouts */
const CHECK_PING_STATUS_INTERVAL = 10 * 1000;
/** A peer is considered long connection if it's >= 1 day */
const LONG_PEER_CONNECTION_MS = 24 * 60 * 60 * 1000;
/** Ref https://github.com/ChainSafe/lodestar/issues/3423 */
const DEFAULT_DISCV5_FIRST_QUERY_DELAY_MS = 1000;
/**
 * Tag peer when it's relevant and connecting to our node.
 * When node has > maxPeer (55), libp2p randomly prune peers if we don't tag peers in use.
 * See https://github.com/ChainSafe/lodestar/issues/4623#issuecomment-1374447934
 **/
const PEER_RELEVANT_TAG = "relevant";
/** Tag value of PEER_RELEVANT_TAG */
const PEER_RELEVANT_TAG_VALUE = 100;

/** Change pruning behavior once the head falls behind */
const STARVATION_THRESHOLD_SLOTS = SLOTS_PER_EPOCH * 2;
/** Percentage of peers to attempt to prune when starvation threshold is met */
const STARVATION_PRUNE_RATIO = 0.05;

/**
 * Relative factor of peers that are allowed to have a negative gossipsub score without penalizing them in lodestar.
 */
const ALLOWED_NEGATIVE_GOSSIPSUB_FACTOR = 0.1;

// TODO:
// maxPeers and targetPeers should be dynamic on the num of validators connected
// The Node should compute a recommended value every interval and log a warning
// to terminal if it deviates significantly from the user's settings

export type PeerManagerOpts = {
  /** The target number of peers we would like to connect to. */
  targetPeers: number;
  /** The maximum number of peers we allow (exceptions for subnet peers) */
  maxPeers: number;
  /** Target peer per PeerDAS group */
  targetGroupPeers: number;
  /**
   * Delay the 1st query after starting discv5
   * See https://github.com/ChainSafe/lodestar/issues/3423
   */
  discv5FirstQueryDelayMs?: number;
  /**
   * If null, Don't run discv5 queries, nor connect to cached peers in the peerStore
   */
  discv5: LodestarDiscv5Opts | null;
  /**
   * If set to true, connect to Discv5 bootnodes. If not set or false, do not connect
   */
  connectToDiscv5Bootnodes?: boolean;
};

/**
 * ReqResp methods used only be PeerManager, so the main thread never has to call them
 */
export interface IReqRespBeaconNodePeerManager {
  sendPing(peerId: PeerId): Promise<phase0.Ping>;
  sendStatus(peerId: PeerId, request: Status): Promise<Status>;
  sendGoodbye(peerId: PeerId, request: phase0.Goodbye): Promise<void>;
  sendMetadata(peerId: PeerId): Promise<Metadata>;
}

export type PeerManagerModules = {
  privateKey: PrivateKey;
  libp2p: Libp2p;
  logger: LoggerNode;
  metrics: NetworkCoreMetrics | null;
  reqResp: IReqRespBeaconNodePeerManager;
  gossip: Eth2Gossipsub;
  attnetsService: SubnetsService;
  syncnetsService: SubnetsService;
  clock: IClock;
  peerRpcScores: IPeerRpcScoreStore;
  events: INetworkEventBus;
  networkConfig: NetworkConfig;
  peersData: PeersData;
  statusCache: StatusCache;
};

export type PeerRequestedSubnetType = SubnetType | "column";

type PeerIdStr = string;

// TODO(fulu): dedupe with network/peers/peerData.ts
enum RelevantPeerStatus {
  Unknown = "unknown",
  relevant = "relevant",
  irrelevant = "irrelevant",
}

/**
 * Performs all peer management functionality in a single grouped class:
 * - Ping peers every `PING_INTERVAL_MS`
 * - Status peers every `STATUS_INTERVAL_MS`
 * - Execute discovery query if under target peers
 * - Execute discovery query if need peers on some subnet: TODO
 * - Disconnect peers if over target peers
 */
export class PeerManager {
  private nodeId: NodeId;
  private readonly libp2p: Libp2p;
  private readonly logger: LoggerNode;
  private readonly metrics: NetworkCoreMetrics | null;
  private readonly reqResp: IReqRespBeaconNodePeerManager;
  private readonly gossipsub: Eth2Gossipsub;
  private readonly attnetsService: SubnetsService;
  private readonly syncnetsService: SubnetsService;
  private readonly clock: IClock;
  private readonly networkConfig: NetworkConfig;
  private readonly config: BeaconConfig;
  private readonly peerRpcScores: IPeerRpcScoreStore;
  /** If null, discovery is disabled */
  private readonly discovery: PeerDiscovery | null;
  private readonly networkEventBus: INetworkEventBus;
  private readonly statusCache: StatusCache;
  private lastStatus: Status;

  // A single map of connected peers with all necessary data to handle PINGs, STATUS, and metrics
  private connectedPeers: Map<PeerIdStr, PeerData>;
  private opts: PeerManagerOpts;
  private intervals: NodeJS.Timeout[] = [];

  constructor(modules: PeerManagerModules, opts: PeerManagerOpts, discovery: PeerDiscovery | null) {
    const {networkConfig} = modules;
    this.libp2p = modules.libp2p;
    this.logger = modules.logger;
    this.metrics = modules.metrics;
    this.reqResp = modules.reqResp;
    this.gossipsub = modules.gossip;
    this.attnetsService = modules.attnetsService;
    this.syncnetsService = modules.syncnetsService;
    this.statusCache = modules.statusCache;
    this.clock = modules.clock;
    this.networkConfig = networkConfig;
    this.config = networkConfig.config;
    this.peerRpcScores = modules.peerRpcScores;
    this.networkEventBus = modules.events;
    this.connectedPeers = modules.peersData.connectedPeers;
    this.opts = opts;
    this.discovery = discovery;
    this.nodeId = networkConfig.nodeId;

    const {metrics} = modules;
    if (metrics) {
      metrics.peers.addCollect(() => this.runPeerCountMetrics(metrics));
    }

    this.libp2p.services.components.events.addEventListener(Libp2pEvent.connectionOpen, this.onLibp2pPeerConnect);
    this.libp2p.services.components.events.addEventListener(Libp2pEvent.connectionClose, this.onLibp2pPeerDisconnect);
    this.networkEventBus.on(NetworkEvent.reqRespRequest, this.onRequest);

    this.lastStatus = this.statusCache.get();

    // A connection may already be open before listeners are attached.
    // Seed those peers so they are tracked in connectedPeers immediately.
    this.bootstrapAlreadyOpenConnections();
    // Defer status/ping to the next event loop tick so the heartbeat interval and
    // event listeners are fully registered before we begin handshakes.
    callInNextEventLoop(() => this.pingAndStatusTimeouts());

    // On start-up will connected to existing peers in libp2p.peerStore, same as autoDial behaviour
    this.heartbeat();
    this.intervals = [
      setInterval(this.pingAndStatusTimeouts.bind(this), CHECK_PING_STATUS_INTERVAL),
      setInterval(this.heartbeat.bind(this), HEARTBEAT_INTERVAL_MS),
      setInterval(
        this.updateGossipsubScores.bind(this),
        this.gossipsub.scoreParams.decayInterval ?? HEARTBEAT_INTERVAL_MS
      ),
    ];
  }

  static async init(modules: PeerManagerModules, opts: PeerManagerOpts): Promise<PeerManager> {
    // opts.discv5 === null, discovery is disabled
    const discovery = opts.discv5
      ? await PeerDiscovery.init(modules, {
          discv5FirstQueryDelayMs: opts.discv5FirstQueryDelayMs ?? DEFAULT_DISCV5_FIRST_QUERY_DELAY_MS,
          discv5: opts.discv5,
          connectToDiscv5Bootnodes: opts.connectToDiscv5Bootnodes,
        })
      : null;

    return new PeerManager(modules, opts, discovery);
  }

  async close(): Promise<void> {
    await this.discovery?.stop();
    this.libp2p.services.components.events.removeEventListener(Libp2pEvent.connectionOpen, this.onLibp2pPeerConnect);
    this.libp2p.services.components.events.removeEventListener(
      Libp2pEvent.connectionClose,
      this.onLibp2pPeerDisconnect
    );
    this.networkEventBus.off(NetworkEvent.reqRespRequest, this.onRequest);
    for (const interval of this.intervals) clearInterval(interval);
  }

  /**
   * Return peers with at least one connection in status "open"
   */
  getConnectedPeerIds(): PeerId[] {
    return getConnectedPeerIds(this.libp2p);
  }

  /**
   * Efficiently check if there is at least one peer connected
   */
  hasSomeConnectedPeer(): boolean {
    return hasSomeConnectedPeer(this.libp2p);
  }

  async goodbyeAndDisconnectAllPeers(): Promise<void> {
    await Promise.all(
      // Filter by peers that support the goodbye protocol: {supportsProtocols: [goodbyeProtocol]}
      this.getConnectedPeerIds().map(async (peer) => this.goodbyeAndDisconnect(peer, GoodByeReasonCode.CLIENT_SHUTDOWN))
    );
  }

  /**
   * Run after validator subscriptions request.
   */
  onCommitteeSubscriptions(): void {
    // TODO:
    // Only if the slot is more than epoch away, add an event to start looking for peers

    // Request to run heartbeat fn
    this.heartbeat();
  }

  reportPeer(peer: PeerId, action: PeerAction, actionName: string): void {
    this.peerRpcScores.applyAction(peer, action, actionName);
  }

  /**
   * The app layer needs to refresh the status of some peers. The sync have reached a target
   */
  reStatusPeers(peers: PeerIdStr[]): void {
    for (const peer of peers) {
      const peerData = this.connectedPeers.get(peer);
      if (peerData) {
        // Set to 0 to trigger a status request after calling pingAndStatusTimeouts()
        peerData.lastStatusUnixTsMs = 0;
      }
    }
    this.pingAndStatusTimeouts();
  }

  dumpPeerScoreStats(): PeerScoreStats {
    return this.peerRpcScores.dumpPeerScoreStats();
  }

  /**
   * Must be called when network ReqResp receives incoming requests
   */
  private onRequest = ({peer, request}: NetworkEventData[NetworkEvent.reqRespRequest]): void => {
    try {
      const peerData = this.connectedPeers.get(peer.toString());
      if (peerData) {
        peerData.lastReceivedMsgUnixTsMs = Date.now();
      }

      switch (request.method) {
        case ReqRespMethod.Ping:
          this.onPing(peer, request.body);
          return;
        case ReqRespMethod.Goodbye:
          this.onGoodbye(peer, request.body);
          return;
        case ReqRespMethod.Status:
          this.onStatus(peer, request.body);
          return;
      }
    } catch (e) {
      this.logger.error("Error onRequest handler", {}, e as Error);
    }
  };

  /**
   * Handle a PING request + response (rpc handler responds with PONG automatically)
   */
  private onPing(peer: PeerId, seqNumber: phase0.Ping): void {
    // if the sequence number is unknown update the peer's metadata
    const metadata = this.connectedPeers.get(peer.toString())?.metadata;
    if (!metadata || metadata.seqNumber < seqNumber) {
      void this.requestMetadata(peer);
    }
  }

  /**
   * Handle a METADATA request + response (rpc handler responds with METADATA automatically)
   */
  private onMetadata(peer: PeerId, metadata: Metadata): void {
    // Store metadata always in case the peer updates attnets but not the sequence number
    // Trust that the peer always sends the latest metadata (From Lighthouse)
    const peerData = this.connectedPeers.get(peer.toString());
    this.logger.debug("onMetadata", {
      peer: peer.toString(),
      peerData: peerData !== undefined,
      custodyGroupCount: (metadata as Partial<fulu.Metadata>)?.custodyGroupCount,
    });
    if (peerData) {
      const oldMetadata = peerData.metadata;
      const custodyGroupCount =
        (metadata as Partial<fulu.Metadata>).custodyGroupCount ?? this.config.CUSTODY_REQUIREMENT;
      const samplingGroupCount = Math.max(this.config.SAMPLES_PER_SLOT, custodyGroupCount);
      const nodeId = peerData?.nodeId ?? computeNodeId(peer);
      const custodyGroups =
        oldMetadata == null || oldMetadata.custodyGroups == null || custodyGroupCount !== oldMetadata.custodyGroupCount
          ? getCustodyGroups(this.config, nodeId, custodyGroupCount)
          : oldMetadata.custodyGroups;
      const oldSamplingGroupCount = Math.max(this.config.SAMPLES_PER_SLOT, oldMetadata?.custodyGroupCount ?? 0);
      const samplingGroups =
        oldMetadata == null || oldMetadata.samplingGroups == null || samplingGroupCount !== oldSamplingGroupCount
          ? getCustodyGroups(this.config, nodeId, samplingGroupCount)
          : oldMetadata.samplingGroups;
      peerData.metadata = {
        seqNumber: metadata.seqNumber,
        attnets: metadata.attnets,
        syncnets: (metadata as Partial<altair.Metadata>).syncnets ?? BitArray.fromBitLen(SYNC_COMMITTEE_SUBNET_COUNT),
        custodyGroupCount:
          (metadata as Partial<fulu.Metadata>).custodyGroupCount ??
          // TODO: spec says that Clients MAY reject peers with a value less than CUSTODY_REQUIREMENT
          this.config.CUSTODY_REQUIREMENT,
        // TODO(fulu): this should be columns not groups.  need to change everywhere. we consume columns and should
        //      cache that instead so if groups->columns ever changes from 1-1 we only need to update that here
        custodyGroups,
        samplingGroups,
      };
      if (oldMetadata === null || oldMetadata.custodyGroupCount !== peerData.metadata.custodyGroupCount) {
        void this.requestStatus(peer, this.statusCache.get());
      }
    }
  }

  /**
   * Handle a GOODBYE request (rpc handler responds automatically)
   */
  private onGoodbye(peer: PeerId, goodbye: phase0.Goodbye): void {
    const reason = GOODBYE_KNOWN_CODES[goodbye.toString()] || "";
    this.logger.verbose("Received goodbye request", {peer: prettyPrintPeerId(peer), goodbye, reason});
    this.metrics?.peerGoodbyeReceived.inc({reason});

    const conn = getConnection(this.libp2p, peer.toString());
    if (conn && Date.now() - conn.timeline.open > LONG_PEER_CONNECTION_MS) {
      this.metrics?.peerLongConnectionDisconnect.inc({reason});
    }

    void this.disconnect(peer);
  }

  /**
   * Handle a STATUS request + response (rpc handler responds with STATUS automatically)
   */
  private onStatus(peer: PeerId, status: Status): void {
    // reset the to-status timer of this peer
    const peerData = this.connectedPeers.get(peer.toString());
    if (peerData) {
      peerData.lastStatusUnixTsMs = Date.now();
      peerData.status = status;
    }

    const forkName = this.config.getForkName(this.clock.currentSlot);

    let isIrrelevant: boolean;
    try {
      const irrelevantReasonType = assertPeerRelevance(
        forkName,
        status,
        this.statusCache.get(),
        this.clock.currentSlot
      );
      if (irrelevantReasonType === null) {
        isIrrelevant = false;
      } else {
        isIrrelevant = true;
        this.logger.debug("Irrelevant peer", {
          peer: prettyPrintPeerId(peer),
          reason: renderIrrelevantPeerType(irrelevantReasonType),
        });
      }
    } catch (e) {
      this.logger.error("Irrelevant peer - unexpected error", {peer: prettyPrintPeerId(peer)}, e as Error);
      isIrrelevant = true;
    }

    if (isIrrelevant) {
      if (peerData) peerData.relevantStatus = RelevantPeerStatus.irrelevant;
      void this.goodbyeAndDisconnect(peer, GoodByeReasonCode.IRRELEVANT_NETWORK);
      return;
    }

    // Peer is usable, send it to the rangeSync
    // NOTE: Peer may not be connected anymore at this point, potential race condition
    // libp2p.connectionManager.get() returns not null if there's +1 open connections with `peer`
    if (peerData && peerData.relevantStatus !== RelevantPeerStatus.relevant) {
      this.libp2p.peerStore
        .merge(peer, {
          // ttl = undefined means it's never expired
          tags: {[PEER_RELEVANT_TAG]: {ttl: undefined, value: PEER_RELEVANT_TAG_VALUE}},
        })
        .catch((e) => this.logger.verbose("cannot tag peer", {peerId: peer.toString()}, e as Error));
      peerData.relevantStatus = RelevantPeerStatus.relevant;
    }
    if (getConnection(this.libp2p, peer.toString())) {
      const nodeId = peerData?.nodeId ?? computeNodeId(peer);
      // TODO(fulu): Are we sure we've run Metadata before this?
      const custodyGroupCount = peerData?.metadata?.custodyGroupCount ?? this.config.CUSTODY_REQUIREMENT;
      const custodyGroups =
        peerData?.metadata?.custodyGroups ?? getCustodyGroups(this.config, nodeId, custodyGroupCount);
      const custodyColumns = custodyGroups
        .flatMap((g) => computeColumnsForCustodyGroup(this.config, g))
        .sort((a, b) => a - b);

      const sampleSubnets = this.networkConfig.custodyConfig.sampledSubnets;
      const matchingSubnetsNum = sampleSubnets.reduce((acc, elem) => acc + (custodyColumns.includes(elem) ? 1 : 0), 0);
      const hasAllColumns = matchingSubnetsNum === sampleSubnets.length;
      const clientAgent = peerData?.agentClient ?? ClientKind.Unknown;

      this.logger.debug("onStatus", {
        nodeId: toHex(nodeId),
        myNodeId: toHex(this.nodeId),
        peerId: peer.toString(),
        custodyGroupCount,
        hasAllColumns,
        matchingSubnetsNum,
        custodyGroups: prettyPrintIndices(custodyGroups),
        custodyColumns: prettyPrintIndices(custodyColumns),
        mySampleSubnets: prettyPrintIndices(sampleSubnets),
        clientAgent,
      });

      this.networkEventBus.emit(NetworkEvent.peerConnected, {
        peer: peer.toString(),
        status,
        clientAgent,
        custodyColumns,
      });

      // Identify peer after status proves the connection is usable.
      // This is the only place we trigger identify — avoids wasted streams on
      // peers that close identify right after connection open or turn out to be
      // irrelevant.
      if (peerData?.agentVersion === null) {
        void this.identifyPeer(peer.toString(), prettyPrintPeerId(peer), getConnection(this.libp2p, peer.toString()));
      }
    }
  }

  private async requestMetadata(peer: PeerId): Promise<void> {
    const peerIdStr = peer.toString();
    try {
      this.onMetadata(peer, await this.reqResp.sendMetadata(peer));
    } catch (e) {
      this.logger.verbose("invalid requestMetadata", {peer: prettyPrintPeerIdStr(peerIdStr)}, e as Error);
      // TODO: Downvote peer here or in the reqResp layer
    }
  }

  private async requestPing(peer: PeerId): Promise<void> {
    const peerIdStr = peer.toString();
    try {
      this.onPing(peer, await this.reqResp.sendPing(peer));

      // If peer replies a PING request also update lastReceivedMsg
      const peerData = this.connectedPeers.get(peer.toString());
      if (peerData) peerData.lastReceivedMsgUnixTsMs = Date.now();
    } catch (e) {
      this.logger.verbose("invalid requestPing", {peer: prettyPrintPeerIdStr(peerIdStr)}, e as Error);
      // TODO: Downvote peer here or in the reqResp layer
    }
  }

  private async requestStatus(peer: PeerId, localStatus: Status): Promise<void> {
    const peerIdStr = peer.toString();
    try {
      this.onStatus(peer, await this.reqResp.sendStatus(peer, localStatus));
    } catch (e) {
      this.logger.verbose("invalid requestStatus", {peer: prettyPrintPeerIdStr(peerIdStr)}, e as Error);
      // TODO: Failed to get peer latest status: downvote but don't disconnect
    }
  }

  private async requestStatusMany(peers: PeerId[]): Promise<void> {
    try {
      const localStatus = this.statusCache.get();
      await Promise.all(peers.map(async (peer) => this.requestStatus(peer, localStatus)));
    } catch (e) {
      this.logger.verbose("Error requesting new status to peers", {}, e as Error);
    }
  }

  /**
   * The Peer manager's heartbeat maintains the peer count and maintains peer reputations.
   * It will request discovery queries if the peer count has not reached the desired number of peers.
   * NOTE: Discovery should only add a new query if one isn't already queued.
   */
  private heartbeat(): void {
    // timer is safe without a try {} catch (_e) {}, in case of error the metric won't register and timer is GC'ed
    const timer = this.metrics?.peerManager.heartbeatDuration.startTimer();

    const connectedPeers = this.getConnectedPeerIds();

    // Decay scores before reading them. Also prunes scores
    this.peerRpcScores.update();

    // ban and disconnect peers with bad score, collect rest of healthy peers
    const connectedHealthyPeers: PeerId[] = [];
    for (const peer of connectedPeers) {
      switch (this.peerRpcScores.getScoreState(peer)) {
        case ScoreState.Banned:
          void this.goodbyeAndDisconnect(peer, GoodByeReasonCode.BANNED);
          break;
        case ScoreState.Disconnected:
          void this.goodbyeAndDisconnect(peer, GoodByeReasonCode.SCORE_TOO_LOW);
          break;
        case ScoreState.Healthy:
          connectedHealthyPeers.push(peer);
      }
    }

    const status = this.statusCache.get();
    const starved =
      // while syncing progress is happening, we aren't starved
      this.lastStatus.headSlot === status.headSlot &&
      // if the head falls behind the threshold, we are starved
      this.clock.currentSlot - status.headSlot > STARVATION_THRESHOLD_SLOTS;
    this.lastStatus = status;
    this.metrics?.peerManager.starved.set(starved ? 1 : 0);
    const forkSeq = this.config.getForkSeq(this.clock.currentSlot);

    const {peersToDisconnect, peersToConnect, attnetQueries, syncnetQueries, custodyGroupQueries} = prioritizePeers(
      connectedHealthyPeers.map((peer) => {
        const peerData = this.connectedPeers.get(peer.toString());
        return {
          id: peer,
          direction: peerData?.direction ?? null,
          status: peerData?.status ?? null,
          attnets: peerData?.metadata?.attnets ?? null,
          syncnets: peerData?.metadata?.syncnets ?? null,
          // here we care samplingGroups not custodyGroups in order to know which column subnets peers subscribe to
          samplingGroups: peerData?.metadata?.samplingGroups ?? null,
          score: this.peerRpcScores.getScore(peer),
        };
      }),
      // Collect subnets which we need peers for in the current slot
      this.attnetsService.getActiveSubnets(),
      this.syncnetsService.getActiveSubnets(),
      // ignore samplingGroups for pre-fulu forks
      forkSeq >= ForkSeq.fulu ? this.networkConfig.custodyConfig.sampleGroups : undefined,
      {
        ...this.opts,
        status,
        starved,
        starvationPruneRatio: STARVATION_PRUNE_RATIO,
        starvationThresholdSlots: STARVATION_THRESHOLD_SLOTS,
      },
      this.config,
      this.metrics
    );

    const queriesMerged: SubnetDiscvQueryMs[] = [];
    for (const {type, queries} of [
      {type: SubnetType.attnets, queries: attnetQueries},
      {type: SubnetType.syncnets, queries: syncnetQueries},
    ]) {
      if (queries.length > 0) {
        let count = 0;
        for (const query of queries) {
          count += query.maxPeersToDiscover;
          queriesMerged.push({
            subnet: query.subnet,
            type,
            maxPeersToDiscover: query.maxPeersToDiscover,
            toUnixMs: computeTimeAtSlot(this.config, query.toSlot, this.clock.genesisTime) * 1000,
          });
        }

        this.metrics?.peersRequestedSubnetsToQuery.inc({type}, queries.length);
        this.metrics?.peersRequestedSubnetsPeerCount.inc({type}, count);
      }
    }

    for (const maxPeersToDiscover of custodyGroupQueries.values()) {
      this.metrics?.peersRequestedSubnetsToQuery.inc({type: "column"}, 1);
      this.metrics?.peersRequestedSubnetsPeerCount.inc({type: "column"}, maxPeersToDiscover);
    }

    // disconnect first to have more slots before we dial new peers
    for (const [reason, peers] of peersToDisconnect) {
      this.metrics?.peersRequestedToDisconnect.inc({reason}, peers.length);
      for (const peer of peers) {
        void this.goodbyeAndDisconnect(peer, GoodByeReasonCode.TOO_MANY_PEERS);
      }
    }

    if (this.discovery) {
      try {
        this.metrics?.peersRequestedToConnect.inc(peersToConnect);
        // for PeerDAS, lodestar implements subnet sampling strategy, hence we need to issue columnSubnetQueries to PeerDiscovery
        this.discovery.discoverPeers(peersToConnect, custodyGroupQueries, queriesMerged);
      } catch (e) {
        this.logger.error("Error on discoverPeers", {}, e as Error);
      }
    }

    // Prune connectedPeers map in case it leaks. It has happen in previous nodes,
    // disconnect is not always called for all peers
    if (this.connectedPeers.size > connectedPeers.length * 1.1) {
      const actualConnectedPeerIds = new Set(connectedPeers.map((peerId) => peerId.toString()));
      for (const peerIdStr of this.connectedPeers.keys()) {
        if (!actualConnectedPeerIds.has(peerIdStr)) {
          this.connectedPeers.delete(peerIdStr);
          this.metrics?.leakedConnectionsCount.inc();
        }
      }
    }

    timer?.();

    this.logger.debug("peerManager heartbeat result", {
      peersToDisconnect: peersToDisconnect.size,
      peersToConnect: peersToConnect,
      attnetQueries: attnetQueries.length,
      syncnetQueries: syncnetQueries.length,
    });
  }

  private updateGossipsubScores(): void {
    const gossipsubScores = new Map<string, number>();
    for (const peerIdStr of this.connectedPeers.keys()) {
      gossipsubScores.set(peerIdStr, this.gossipsub.getScore(peerIdStr));
    }

    const toIgnoreNegativePeers = Math.ceil(this.opts.targetPeers * ALLOWED_NEGATIVE_GOSSIPSUB_FACTOR);
    updateGossipsubScores(this.peerRpcScores, gossipsubScores, toIgnoreNegativePeers);
  }

  private pingAndStatusTimeouts(): void {
    const now = Date.now();
    const peersToStatus: PeerId[] = [];

    for (const peer of this.connectedPeers.values()) {
      // Every interval request to send some peers our seqNumber and process theirs
      // If the seqNumber is different it must request the new metadata
      const pingInterval = peer.direction === "inbound" ? PING_INTERVAL_INBOUND_MS : PING_INTERVAL_OUTBOUND_MS;
      if (now > peer.lastReceivedMsgUnixTsMs + pingInterval) {
        void this.requestPing(peer.peerId);
      }

      // TODO: Consider sending status request to peers that do support status protocol
      // {supportsProtocols: getStatusProtocols()}

      // Every interval request to send some peers our status, and process theirs
      // Must re-check if this peer is relevant to us and emit an event if the status changes
      // So the sync layer can update things
      if (now > peer.lastStatusUnixTsMs + STATUS_INTERVAL_MS) {
        peersToStatus.push(peer.peerId);
      }
    }

    if (peersToStatus.length > 0) {
      void this.requestStatusMany(peersToStatus);
    }
  }

  private bootstrapAlreadyOpenConnections(): void {
    let bootstrapped = 0;

    for (const {value: connections} of getConnectionsMap(this.libp2p).values()) {
      for (const connection of connections) {
        // trackLibp2pConnection handles deduplication via overwriteExisting: false
        if (this.trackLibp2pConnection(connection, {overwriteExisting: false, triggerHandshakeNow: false})) {
          bootstrapped++;
        }
      }
    }

    if (bootstrapped > 0) {
      this.logger.verbose("Bootstrapped already-open libp2p peers", {bootstrapped});
    }
  }

  private trackLibp2pConnection(
    connection: Connection,
    opts: {overwriteExisting: boolean; triggerHandshakeNow: boolean}
  ): boolean {
    const {direction, status, remotePeer} = connection;
    const remotePeerStr = remotePeer.toString();
    const remotePeerPrettyStr = prettyPrintPeerId(remotePeer);

    if (status !== "open") {
      this.logger.debug("Peer disconnected before identify protocol initiated", {
        peerId: remotePeerPrettyStr,
        status,
      });
      return false;
    }

    // Ethereum uses secp256k1 for node IDs, reject peers with other key types
    if (remotePeer.type !== "secp256k1") {
      this.logger.debug("Peer does not have secp256k1 key, disconnecting", {
        peer: remotePeerPrettyStr,
        type: remotePeer.type,
      });
      void this.goodbyeAndDisconnect(remotePeer, GoodByeReasonCode.IRRELEVANT_NETWORK);
      return false;
    }

    if (!opts.overwriteExisting && this.connectedPeers.has(remotePeerStr)) {
      return false;
    }

    // On connection:
    // - Outbound connections: send a STATUS and PING request
    // - Inbound connections: expect to be STATUS'd, schedule STATUS and PING for later
    // NOTE: libp2p may emit two "peer:connect" events: One for inbound, one for outbound
    // If that happens, it's okay. Only the "outbound" connection triggers immediate action
    const now = Date.now();
    const existingPeerData = this.connectedPeers.get(remotePeerStr);
    const nodeId = computeNodeId(remotePeer);
    const peerData: PeerData = {
      // Keep existing timestamps if this peer already had another open connection.
      // libp2p may emit multiple connection:open events per peer.
      lastReceivedMsgUnixTsMs: existingPeerData?.lastReceivedMsgUnixTsMs ?? (direction === "outbound" ? 0 : now),
      // If inbound, request after STATUS_INBOUND_GRACE_PERIOD
      lastStatusUnixTsMs:
        existingPeerData?.lastStatusUnixTsMs ??
        (direction === "outbound" ? 0 : now - STATUS_INTERVAL_MS + STATUS_INBOUND_GRACE_PERIOD),
      connectedUnixTsMs: existingPeerData?.connectedUnixTsMs ?? now,
      relevantStatus: existingPeerData?.relevantStatus ?? RelevantPeerStatus.Unknown,
      direction,
      nodeId,
      peerId: remotePeer,
      status: existingPeerData?.status ?? null,
      metadata: existingPeerData?.metadata ?? null,
      agentVersion: existingPeerData?.agentVersion ?? null,
      agentClient: existingPeerData?.agentClient ?? null,
      encodingPreference: existingPeerData?.encodingPreference ?? null,
    };
    this.connectedPeers.set(remotePeerStr, peerData);

    if (direction === "outbound" && opts.triggerHandshakeNow) {
      void this.requestPing(remotePeer);
      void this.requestStatus(remotePeer, this.statusCache.get());
    }

    return true;
  }

  /**
   * The libp2p Upgrader has successfully upgraded a peer connection on a particular multiaddress
   * This event is routed through the connectionManager
   *
   * Registers a peer as connected. The `direction` parameter determines if the peer is being
   * dialed or connecting to us.
   */
  private onLibp2pPeerConnect = (evt: CustomEvent<Connection>): void => {
    const {direction, status, remotePeer} = evt.detail;
    this.logger.verbose("peer connected", {peer: prettyPrintPeerId(remotePeer), direction, status});
    // NOTE: The peerConnect event is not emitted here here, but after asserting peer relevance
    this.metrics?.peerConnectedEvent.inc({direction, status});

    this.trackLibp2pConnection(evt.detail, {overwriteExisting: true, triggerHandshakeNow: true});
  };

  /**
   * The libp2p Upgrader has ended a connection
   */
  private onLibp2pPeerDisconnect = (evt: CustomEvent<Connection>): void => {
    const {direction, status, remotePeer} = evt.detail;
    const peerIdStr = remotePeer.toString();

    const openConnections =
      getConnectionsMap(this.libp2p)
        .get(peerIdStr)
        ?.value.filter((connection) => connection.status === "open") ?? [];
    if (openConnections.length > 0) {
      this.logger.debug("Ignoring peer disconnect event while another connection is still open", {
        peerId: prettyPrintPeerIdStr(peerIdStr),
        direction,
        status,
      });
      return;
    }

    let logMessage = "onLibp2pPeerDisconnect";
    const logContext: Record<string, string | number> = {
      peerId: prettyPrintPeerIdStr(peerIdStr),
      direction,
      status,
    };
    // Some clients do not send good-bye requests (Nimbus) so check for inbound disconnects and apply reconnection
    // cool-down period to prevent automatic reconnection by Discovery
    if (direction === "inbound") {
      // prevent automatic/immediate reconnects
      const coolDownMin = this.peerRpcScores.applyReconnectionCoolDown(peerIdStr, GoodByeReasonCode.INBOUND_DISCONNECT);
      logMessage += ". Enforcing a reconnection cool-down period";
      logContext.coolDownMin = coolDownMin;
    }

    // remove the ping and status timer for the peer
    this.connectedPeers.delete(peerIdStr);

    this.logger.verbose(logMessage, logContext);
    this.networkEventBus.emit(NetworkEvent.peerDisconnected, {peer: peerIdStr});
    this.metrics?.peerDisconnectedEvent.inc({direction});
    this.libp2p.peerStore
      .merge(remotePeer, {tags: {[PEER_RELEVANT_TAG]: undefined}})
      .catch((e) => this.logger.verbose("cannot untag peer", {peerId: peerIdStr}, e as Error));
  };

  private async disconnect(peer: PeerId): Promise<void> {
    try {
      await this.libp2p.hangUp(peer);
    } catch (e) {
      this.logger.debug("Unclean disconnect", {peer: prettyPrintPeerId(peer)}, e as Error);
    }
  }

  private async identifyPeer(peerIdStr: string, peerIdPretty: string, connection?: Connection): Promise<void> {
    if (!connection || connection.status !== "open") {
      this.logger.debug("Peer has no open connection for identify", {peerId: peerIdPretty});
      return;
    }

    try {
      const result = await this.libp2p.services.identify.identify(connection);
      const agentVersion = result.agentVersion;
      if (agentVersion) {
        const connectedPeerData = this.connectedPeers.get(peerIdStr);
        if (connectedPeerData) {
          connectedPeerData.agentVersion = agentVersion;
          connectedPeerData.agentClient = getKnownClientFromAgentVersion(agentVersion);
        }
      }
    } catch (e) {
      this.logger.debug("Error setting agentVersion for the peer", {peerId: peerIdPretty}, e as Error);
    }
  }

  private async goodbyeAndDisconnect(peer: PeerId, goodbye: GoodByeReasonCode): Promise<void> {
    const reason = GOODBYE_KNOWN_CODES[goodbye.toString()] || "";
    const peerIdStr = peer.toString();
    try {
      this.metrics?.peerGoodbyeSent.inc({reason});
      this.logger.debug("initiating goodbyeAndDisconnect peer", {reason, peerId: prettyPrintPeerId(peer)});

      const conn = getConnection(this.libp2p, peerIdStr);
      if (conn && Date.now() - conn.timeline.open > LONG_PEER_CONNECTION_MS) {
        this.metrics?.peerLongConnectionDisconnect.inc({reason});
      }

      // Wrap with shorter timeout than regular ReqResp requests to speed up shutdown
      await withTimeout(() => this.reqResp.sendGoodbye(peer, BigInt(goodbye)), 1_000);
    } catch (e) {
      this.logger.verbose("Failed to send goodbye", {peer: prettyPrintPeerId(peer)}, e as Error);
    } finally {
      await this.disconnect(peer);
      // prevent automatic/immediate reconnects
      const coolDownMin = this.peerRpcScores.applyReconnectionCoolDown(peerIdStr, goodbye);
      if (coolDownMin === NO_COOL_DOWN_APPLIED) {
        this.logger.verbose("Disconnected a peer", {peerId: prettyPrintPeerIdStr(peerIdStr)});
      } else {
        this.logger.verbose("Disconnected a peer. Enforcing a reconnection cool-down period", {
          peerId: prettyPrintPeerIdStr(peerIdStr),
          coolDownMin,
        });
      }
    }
  }

  /** Register peer count metrics */
  private async runPeerCountMetrics(metrics: NetworkCoreMetrics): Promise<void> {
    let total = 0;

    const peersByDirection = new Map<string, number>();
    const peersByClient = new Map<string, number>();
    const now = Date.now();

    // peerLongLivedAttnets metric is a count
    metrics.peerLongLivedAttnets.reset();
    metrics.peerScoreByClient.reset();
    metrics.peerConnectionLength.reset();
    metrics.peerGossipScoreByClient.reset();

    // reset client counts _for each client_ to 0
    for (const client of Object.values(ClientKind)) {
      peersByClient.set(client, 0);
    }

    for (const connections of getConnectionsMap(this.libp2p).values()) {
      const openCnx = connections.value.find((cnx) => cnx.status === "open");
      if (openCnx) {
        const direction = openCnx.direction;
        peersByDirection.set(direction, 1 + (peersByDirection.get(direction) ?? 0));
        const peerId = openCnx.remotePeer;
        const peerData = this.connectedPeers.get(peerId.toString());
        const client = peerData?.agentClient ?? ClientKind.Unknown;
        peersByClient.set(client, 1 + (peersByClient.get(client) ?? 0));

        const attnets = peerData?.metadata?.attnets;

        // TODO: Consider optimizing by doing observe in batch
        metrics.peerLongLivedAttnets.observe(attnets ? attnets.getTrueBitIndexes().length : 0);
        metrics.peerColumnGroupCount.observe(peerData?.metadata?.custodyGroupCount ?? 0);
        metrics.peerScoreByClient.observe({client}, this.peerRpcScores.getScore(peerId));
        metrics.peerGossipScoreByClient.observe({client}, this.peerRpcScores.getGossipScore(peerId));
        metrics.peerConnectionLength.observe((now - openCnx.timeline.open) / 1000);
        total++;
      }
    }

    for (const [direction, peers] of peersByDirection.entries()) {
      metrics.peersByDirection.set({direction}, peers);
    }

    for (const [client, peers] of peersByClient.entries()) {
      metrics.peersByClient.set({client}, peers);
    }

    let syncPeers = 0;
    for (const peer of this.connectedPeers.values()) {
      if (peer.relevantStatus === RelevantPeerStatus.relevant) {
        syncPeers++;
      }
    }

    metrics.peers.set(total);
    metrics.peersSync.set(syncPeers);
  }
}
```

---


## peers/peersData.ts

```typescript
import {PeerId} from "@libp2p/interface";
import {Encoding} from "@lodestar/reqresp";
import {CustodyIndex, Slot, Status, fulu} from "@lodestar/types";
import {NodeId} from "../subnets/interface.js";
import {ClientKind} from "./client.js";

type PeerIdStr = string;
type Metadata = fulu.Metadata & {custodyGroups: CustodyIndex[]; samplingGroups: CustodyIndex[]};
export type PeerSyncMeta = {
  peerId: PeerIdStr;
  client: string;
  custodyColumns: CustodyIndex[];
  earliestAvailableSlot?: Slot;
};

export enum RelevantPeerStatus {
  Unknown = "unknown",
  relevant = "relevant",
  irrelevant = "irrelevant",
}

export type PeerData = {
  lastReceivedMsgUnixTsMs: number;
  lastStatusUnixTsMs: number;
  connectedUnixTsMs: number;
  relevantStatus: RelevantPeerStatus;
  direction: "inbound" | "outbound";
  peerId: PeerId;
  nodeId: NodeId | null;
  metadata: Metadata | null;
  status: Status | null;
  agentVersion: string | null;
  agentClient: ClientKind | null;
  encodingPreference: Encoding | null;
};

/**
 * Make data available to multiple components in the network stack.
 * Due to class dependencies some modules have circular dependencies, like PeerManager - ReqResp.
 * This third party class allows data to be available to both.
 *
 * The pruning and bounding of this class is handled by the PeerManager
 */
export class PeersData {
  readonly connectedPeers = new Map<PeerIdStr, PeerData>();

  getAgentVersion(peerIdStr: string): string {
    return this.connectedPeers.get(peerIdStr)?.agentVersion ?? "NA";
  }

  getPeerKind(peerIdStr: string): ClientKind | null {
    return this.connectedPeers.get(peerIdStr)?.agentClient ?? null;
  }

  getEncodingPreference(peerIdStr: string): Encoding | null {
    return this.connectedPeers.get(peerIdStr)?.encodingPreference ?? null;
  }

  setEncodingPreference(peerIdStr: string, encoding: Encoding): void {
    const peerData = this.connectedPeers.get(peerIdStr);
    if (peerData) {
      peerData.encodingPreference = encoding;
    }
  }
}
```

---


## peers/client.ts

```typescript
export enum ClientKind {
  Lighthouse = "Lighthouse",
  Nimbus = "Nimbus",
  Teku = "Teku",
  Prysm = "Prysm",
  Lodestar = "Lodestar",
  Grandine = "Grandine",
  Unknown = "Unknown",
}

/**
 * Get known client from agent version.
 * If client is not known, don't return ClientKind.Unknown here.
 * For metrics it'll have fallback logic to use ClientKind.Unknown
 * For logs, we want to print out agentVersion instead for debugging purposes.
 */
export function getKnownClientFromAgentVersion(agentVersion: string): ClientKind | null {
  const slashIndex = agentVersion.indexOf("/");
  const agent = slashIndex >= 0 ? agentVersion.slice(0, slashIndex) : agentVersion;
  const agentLC = agent.toLowerCase();
  if (agentLC === "lighthouse") return ClientKind.Lighthouse;
  if (agentLC === "teku") return ClientKind.Teku;
  if (agentLC === "prysm") return ClientKind.Prysm;
  if (agentLC === "nimbus") return ClientKind.Nimbus;
  if (agentLC === "grandine") return ClientKind.Grandine;
  if (agentLC === "lodestar" || agentLC === "js-libp2p") return ClientKind.Lodestar;

  return null;
}
```

---


## peers/discover.ts

```typescript
import type {PeerId, PeerInfo, PendingDial, PrivateKey} from "@libp2p/interface";
import {Multiaddr} from "@multiformats/multiaddr";
import {ENR} from "@chainsafe/enr";
import {BeaconConfig} from "@lodestar/config";
import {LoggerNode} from "@lodestar/logger/node";
import {ATTESTATION_SUBNET_COUNT, ForkSeq, SYNC_COMMITTEE_SUBNET_COUNT} from "@lodestar/params";
import {CustodyIndex, SubnetID} from "@lodestar/types";
import {bytesToInt, pruneSetToMax, sleep, toHex} from "@lodestar/utils";
import {IClock} from "../../util/clock.js";
import {getCustodyGroups} from "../../util/dataColumns.js";
import {NetworkCoreMetrics} from "../core/metrics.js";
import {Discv5Worker} from "../discv5/index.js";
import {LodestarDiscv5Opts} from "../discv5/types.js";
import {Libp2p} from "../interface.js";
import {getLibp2pError} from "../libp2p/error.js";
import {ENRKey, SubnetType} from "../metadata.js";
import {NetworkConfig} from "../networkConfig.js";
import {computeNodeId} from "../subnets/interface.js";
import {getConnectionsMap, prettyPrintPeerId} from "../util.js";
import {IPeerRpcScoreStore, ScoreState} from "./score/index.js";
import {deserializeEnrSubnets, zeroAttnets, zeroSyncnets} from "./utils/enrSubnetsDeserialize.js";
import {type CustodyGroupQueries} from "./utils/prioritizePeers.js";

/** Max number of cached ENRs after discovering a good peer */
const MAX_CACHED_ENRS = 100;
/** Max age a cached ENR will be considered for dial */
const MAX_CACHED_ENR_AGE_MS = 5 * 60 * 1000;

export type PeerDiscoveryOpts = {
  discv5FirstQueryDelayMs: number;
  discv5: LodestarDiscv5Opts;
  connectToDiscv5Bootnodes?: boolean;
};

export type PeerDiscoveryModules = {
  privateKey: PrivateKey;
  networkConfig: NetworkConfig;
  libp2p: Libp2p;
  clock: IClock;
  peerRpcScores: IPeerRpcScoreStore;
  metrics: NetworkCoreMetrics | null;
  logger: LoggerNode;
};

type PeerIdStr = string;

enum QueryStatusCode {
  NotActive,
  Active,
}
type QueryStatus = {code: QueryStatusCode.NotActive} | {code: QueryStatusCode.Active; count: number};

export enum DiscoveredPeerStatus {
  bad_score = "bad_score",
  already_connected = "already_connected",
  already_dialing = "already_dialing",
  error = "error",
  attempt_dial = "attempt_dial",
  cached = "cached",
  dropped = "dropped",
  no_multiaddrs = "no_multiaddrs",
  transport_incompatible = "transport_incompatible",
  peer_cooling_down = "peer_cooling_down",
}

export enum NotDialReason {
  not_contain_requested_sampling_groups = "not_contain_requested_sampling_groups",
  not_contain_requested_attnet_syncnet_subnets = "not_contain_requested_attnet_syncnet_subnets",
  no_multiaddrs = "no_multiaddrs",
}

type UnixMs = number;
/**
 * Maintain peersToConnect to avoid having too many topic peers at some point.
 * See https://github.com/ChainSafe/lodestar/issues/5741#issuecomment-1643113577
 */
type SubnetRequestInfo = {
  toUnixMs: UnixMs;
  // when node is stable this should be 0
  peersToConnect: number;
};

export type SubnetDiscvQueryMs = {
  subnet: SubnetID;
  type: SubnetType;
  toUnixMs: UnixMs;
  maxPeersToDiscover: number;
};

type CachedENR = {
  peerId: PeerId;
  multiaddrTCP?: Multiaddr;
  multiaddrQUIC?: Multiaddr;
  subnets: Record<SubnetType, boolean[]>;
  addedUnixMs: number;
  // custodyGroups is null for pre-fulu
  custodyGroups: number[] | null;
};

/**
 * PeerDiscovery discovers and dials new peers, and executes discv5 queries.
 * Currently relies on discv5 automatic periodic queries.
 */
export class PeerDiscovery {
  readonly discv5: Discv5Worker;
  private libp2p: Libp2p;
  private readonly clock: IClock;
  private peerRpcScores: IPeerRpcScoreStore;
  private metrics: NetworkCoreMetrics | null;
  private logger: LoggerNode;
  private config: BeaconConfig;
  private cachedENRs = new Map<PeerIdStr, CachedENR>();
  private randomNodeQuery: QueryStatus = {code: QueryStatusCode.NotActive};
  private peersToConnect = 0;
  private subnetRequests: Record<SubnetType, Map<number, SubnetRequestInfo>> = {
    attnets: new Map(),
    syncnets: new Map(),
  };
  private transports: string[];

  private custodyGroupQueries: CustodyGroupQueries;

  private discv5StartMs: number;
  private discv5FirstQueryDelayMs: number;

  private connectToDiscv5BootnodesOnStart: boolean | undefined = false;

  constructor(modules: PeerDiscoveryModules, opts: PeerDiscoveryOpts, discv5: Discv5Worker) {
    const {libp2p, clock, peerRpcScores, metrics, logger, networkConfig} = modules;
    this.libp2p = libp2p;
    this.clock = clock;
    this.peerRpcScores = peerRpcScores;
    this.metrics = metrics;
    this.logger = logger;
    this.config = networkConfig.config;
    this.discv5 = discv5;
    this.custodyGroupQueries = new Map();

    this.discv5StartMs = 0;
    this.discv5StartMs = Date.now();
    this.discv5FirstQueryDelayMs = opts.discv5FirstQueryDelayMs;
    this.connectToDiscv5BootnodesOnStart = opts.connectToDiscv5Bootnodes;

    this.libp2p.addEventListener("peer:discovery", this.onDiscoveredPeer);
    this.discv5.on("discovered", this.onDiscoveredENR);

    const numBootEnrs = opts.discv5.bootEnrs.length;
    if (numBootEnrs === 0) {
      this.logger.error("PeerDiscovery: discv5 has no boot enr");
    } else {
      this.logger.verbose("PeerDiscovery: number of bootEnrs", {bootEnrs: numBootEnrs});
    }

    if (this.connectToDiscv5BootnodesOnStart) {
      // In devnet scenarios, especially, we want more control over which peers we connect to.
      // Only dial the discv5.bootEnrs if the option
      // network.connectToDiscv5Bootnodes has been set to true.
      for (const bootENR of opts.discv5.bootEnrs) {
        this.onDiscoveredENR(ENR.decodeTxt(bootENR)).catch((e) =>
          this.logger.error("error onDiscoveredENR bootENR", {}, e)
        );
      }
    }

    if (metrics) {
      metrics.discovery.cachedENRsSize.addCollect(() => {
        metrics.discovery.cachedENRsSize.set(this.cachedENRs.size);
        metrics.discovery.peersToConnect.set(this.peersToConnect);

        // PeerDAS metrics
        const groupsToConnect = Array.from(this.custodyGroupQueries.values());
        const groupPeersToConnect = groupsToConnect.reduce((acc, elem) => acc + elem, 0);
        metrics.discovery.custodyGroupPeersToConnect.set(groupPeersToConnect);
        metrics.discovery.custodyGroupsToConnect.set(groupsToConnect.filter((elem) => elem > 0).length);

        for (const type of [SubnetType.attnets, SubnetType.syncnets]) {
          const subnetPeersToConnect = Array.from(this.subnetRequests[type].values()).reduce(
            (acc, {peersToConnect}) => acc + peersToConnect,
            0
          );
          metrics.discovery.subnetPeersToConnect.set({type}, subnetPeersToConnect);
          metrics.discovery.subnetsToConnect.set({type}, this.subnetRequests[type].size);
        }
      });
    }

    // Transport tags vary by library: @libp2p/tcp uses '@libp2p/tcp', @chainsafe/libp2p-quic uses 'quic'
    // Normalize to simple 'tcp' / 'quic' strings for matching
    this.transports = libp2p.services.components.transportManager
      .getTransports()
      .map((t) => t[Symbol.toStringTag])
      .map((tag) => {
        if (tag?.includes("tcp")) return "tcp";
        if (tag?.includes("quic")) return "quic";
        return tag;
      });
  }

  static async init(modules: PeerDiscoveryModules, opts: PeerDiscoveryOpts): Promise<PeerDiscovery> {
    const discv5 = await Discv5Worker.init({
      discv5: opts.discv5,
      privateKey: modules.privateKey,
      metrics: modules.metrics ?? undefined,
      logger: modules.logger,
      config: modules.networkConfig.config,
      genesisTime: modules.clock.genesisTime,
    });

    return new PeerDiscovery(modules, opts, discv5);
  }

  async stop(): Promise<void> {
    this.libp2p.removeEventListener("peer:discovery", this.onDiscoveredPeer);
    this.discv5.off("discovered", this.onDiscoveredENR);
    await this.discv5.close();
  }

  /**
   * Request to find peers, both on specific subnets and in general
   * pre-fulu custodyGroupRequests is empty
   */
  discoverPeers(
    peersToConnect: number,
    custodyGroupRequests: CustodyGroupQueries,
    subnetRequests: SubnetDiscvQueryMs[] = []
  ): void {
    const subnetsToDiscoverPeers: SubnetDiscvQueryMs[] = [];
    const cachedENRsToDial = new Map<PeerIdStr, CachedENR>();
    // Iterate in reverse to consider first the most recent ENRs
    const cachedENRsReverse: CachedENR[] = [];
    const pendingDials = new Set(
      this.libp2p.services.components.connectionManager
        .getDialQueue()
        .map((pendingDial: PendingDial) => pendingDial.peerId?.toString())
    );
    for (const [id, cachedENR] of this.cachedENRs.entries()) {
      if (
        // time expired or
        Date.now() - cachedENR.addedUnixMs > MAX_CACHED_ENR_AGE_MS ||
        // already dialing
        pendingDials.has(id)
      ) {
        this.cachedENRs.delete(id);
      } else if (!this.peerRpcScores.isCoolingDown(id)) {
        cachedENRsReverse.push(cachedENR);
      }
    }
    cachedENRsReverse.reverse();

    this.peersToConnect += peersToConnect;

    // starting from PeerDAS, we need to prioritize column subnet peers first in order to have stable subnet sampling
    const groupsToDiscover = new Set<CustodyIndex>();
    let groupPeersToDiscover = 0;

    const forkSeq = this.config.getForkSeq(this.clock.currentSlot);
    if (forkSeq >= ForkSeq.fulu) {
      group: for (const [group, maxPeersToConnect] of custodyGroupRequests) {
        let cachedENRsInGroup = 0;
        for (const cachedENR of cachedENRsReverse) {
          if (cachedENR.custodyGroups?.includes(group)) {
            cachedENRsToDial.set(cachedENR.peerId.toString(), cachedENR);

            if (++cachedENRsInGroup >= maxPeersToConnect) {
              continue group;
            }
          }

          const groupPeersToConnect = Math.max(maxPeersToConnect - cachedENRsInGroup, 0);
          this.custodyGroupQueries.set(group, groupPeersToConnect);
          groupsToDiscover.add(group);
          groupPeersToDiscover += groupPeersToConnect;
        }
      }
    }

    subnet: for (const subnetRequest of subnetRequests) {
      // Get cached ENRs from the discovery service that are in the requested `subnetId`, but not connected yet
      let cachedENRsInSubnet = 0;

      // only dial attnet/syncnet peers if subnet sampling peers are stable
      if (groupPeersToDiscover === 0) {
        for (const cachedENR of cachedENRsReverse) {
          if (cachedENR.subnets[subnetRequest.type][subnetRequest.subnet]) {
            cachedENRsToDial.set(cachedENR.peerId.toString(), cachedENR);

            if (++cachedENRsInSubnet >= subnetRequest.maxPeersToDiscover) {
              continue subnet;
            }
          }
        }
      }

      const subnetPeersToConnect = Math.max(subnetRequest.maxPeersToDiscover - cachedENRsInSubnet, 0);

      // Extend the toUnixMs for this subnet
      const prevUnixMs = this.subnetRequests[subnetRequest.type].get(subnetRequest.subnet)?.toUnixMs;
      const newUnixMs =
        prevUnixMs !== undefined && prevUnixMs > subnetRequest.toUnixMs ? prevUnixMs : subnetRequest.toUnixMs;
      this.subnetRequests[subnetRequest.type].set(subnetRequest.subnet, {
        toUnixMs: newUnixMs,
        peersToConnect: subnetPeersToConnect,
      });

      // Query a discv5 query if more peers are needed
      subnetsToDiscoverPeers.push(subnetRequest);
    }

    // If subnetRequests won't connect enough peers for peersToConnect, add more
    if (cachedENRsToDial.size < peersToConnect) {
      for (const cachedENR of cachedENRsReverse) {
        cachedENRsToDial.set(cachedENR.peerId.toString(), cachedENR);
        if (cachedENRsToDial.size >= peersToConnect) {
          break;
        }
      }
    }

    // Queue an outgoing connection request to the cached peers that are on `s.subnet_id`.
    // If we connect to the cached peers before the discovery query starts, then we potentially
    // save a costly discovery query.
    for (const [id, cachedENRToDial] of cachedENRsToDial) {
      this.cachedENRs.delete(id);
      void this.dialPeer(cachedENRToDial);
    }

    // Run a discv5 subnet query to try to discover new peers
    const shouldRunFindRandomNodeQuery = subnetsToDiscoverPeers.length > 0 || cachedENRsToDial.size < peersToConnect;
    if (shouldRunFindRandomNodeQuery) {
      void this.runFindRandomNodeQuery();
    }

    this.logger.debug("Discover peers outcome", {
      peersToConnect,
      peersAvailableToDial: cachedENRsToDial.size,
      subnetsToDiscover: subnetsToDiscoverPeers.length,
      groupsToDiscover: Array.from(groupsToDiscover).join(","),
      groupPeersToDiscover,
      shouldRunFindRandomNodeQuery,
    });
  }

  /**
   * Request discv5 to find peers if there is no query in progress
   */
  private async runFindRandomNodeQuery(): Promise<void> {
    // Delay the 1st query after starting discv5
    // See https://github.com/ChainSafe/lodestar/issues/3423
    const msSinceDiscv5Start = Date.now() - this.discv5StartMs;
    if (msSinceDiscv5Start <= this.discv5FirstQueryDelayMs) {
      await sleep(this.discv5FirstQueryDelayMs - msSinceDiscv5Start);
    }

    // Run a general discv5 query if one is not already in progress
    if (this.randomNodeQuery.code === QueryStatusCode.Active) {
      this.metrics?.discovery.findNodeQueryRequests.inc({action: "ignore"});
      return;
    }
    this.metrics?.discovery.findNodeQueryRequests.inc({action: "start"});

    // Use async version to prevent blocking the event loop
    // Time to completion of this function is not critical, in case this async call add extra lag
    this.randomNodeQuery = {code: QueryStatusCode.Active, count: 0};
    const timer = this.metrics?.discovery.findNodeQueryTime.startTimer();

    try {
      const enrs = await this.discv5.findRandomNode();
      this.metrics?.discovery.findNodeQueryEnrCount.inc(enrs.length);
    } catch (e) {
      this.logger.error("Error on discv5.findNode()", {}, e as Error);
    } finally {
      this.randomNodeQuery = {code: QueryStatusCode.NotActive};
      timer?.();
    }
  }

  /**
   * Progressively called by libp2p as a result of peer discovery or updates to its peer store
   */
  private onDiscoveredPeer = (evt: CustomEvent<PeerInfo>): void => {
    const {id, multiaddrs} = evt.detail;

    // libp2p may send us PeerInfos without multiaddrs https://github.com/libp2p/js-libp2p/issues/1873
    if (!multiaddrs || multiaddrs.length === 0) {
      this.metrics?.discovery.discoveredStatus.inc({status: DiscoveredPeerStatus.no_multiaddrs});
      return;
    }

    // Select multiaddrs by protocol rather than index — libp2p discovery events
    // don't guarantee ordering or number of addresses
    const multiaddrTCP = multiaddrs.find((ma) => ma.toString().includes("/tcp/"));
    const multiaddrQUIC = multiaddrs.find((ma) => ma.toString().includes("/quic-v1"));

    const attnets = zeroAttnets;
    const syncnets = zeroSyncnets;

    const status = this.handleDiscoveredPeer(id, multiaddrTCP, multiaddrQUIC, attnets, syncnets, undefined);
    this.logger.debug("Discovered peer via libp2p", {peer: prettyPrintPeerId(id), status});
    this.metrics?.discovery.discoveredStatus.inc({status});
  };

  /**
   * Progressively called by discv5 as a result of any query.
   */
  private onDiscoveredENR = async (enr: ENR): Promise<void> => {
    if (this.randomNodeQuery.code === QueryStatusCode.Active) {
      this.randomNodeQuery.count++;
    }
    const peerId = enr.peerId;
    // At least one transport is known to be present, checked inside the worker
    const multiaddrTCP = enr.getLocationMultiaddr(ENRKey.tcp);
    const multiaddrQUIC = enr.getLocationMultiaddr(ENRKey.quic);
    if (!multiaddrTCP && !multiaddrQUIC) {
      this.logger.warn("Discv5 worker sent enr without any transport multiaddr", {enr: enr.encodeTxt()});
      this.metrics?.discovery.discoveredStatus.inc({status: DiscoveredPeerStatus.no_multiaddrs});
      return;
    }

    // Are this fields mandatory?
    const attnetsBytes = enr.kvs.get(ENRKey.attnets); // 64 bits
    const syncnetsBytes = enr.kvs.get(ENRKey.syncnets); // 4 bits
    const custodyGroupCountBytes = enr.kvs.get(ENRKey.cgc); // not preserialized value, is byte representation of number
    if (custodyGroupCountBytes === undefined) {
      this.logger.debug("peer discovered with no cgc, using default/miniumn", {
        custodyRequirement: this.config.CUSTODY_REQUIREMENT,
        peer: prettyPrintPeerId(peerId),
      });
    }

    // Use faster version than ssz's implementation that leverages pre-cached.
    // Some nodes don't serialize the bitfields properly, encoding the syncnets as attnets,
    // which cause the ssz implementation to throw on validation. deserializeEnrSubnets() will
    // never throw and treat too long or too short bitfields as zero-ed
    const attnets = attnetsBytes ? deserializeEnrSubnets(attnetsBytes, ATTESTATION_SUBNET_COUNT) : zeroAttnets;
    const syncnets = syncnetsBytes ? deserializeEnrSubnets(syncnetsBytes, SYNC_COMMITTEE_SUBNET_COUNT) : zeroSyncnets;
    const custodyGroupCount = custodyGroupCountBytes ? bytesToInt(custodyGroupCountBytes, "be") : undefined;

    const status = this.handleDiscoveredPeer(peerId, multiaddrTCP, multiaddrQUIC, attnets, syncnets, custodyGroupCount);
    this.logger.debug("Discovered peer via discv5", {
      peer: prettyPrintPeerId(peerId),
      status,
      cgc: custodyGroupCount,
    });
    this.metrics?.discovery.discoveredStatus.inc({status});
  };

  /**
   * Progressively called by peer discovery as a result of any query.
   */
  private handleDiscoveredPeer(
    peerId: PeerId,
    multiaddrTCP: Multiaddr | undefined,
    multiaddrQUIC: Multiaddr | undefined,
    attnets: boolean[],
    syncnets: boolean[],
    custodySubnetCount?: number
  ): DiscoveredPeerStatus {
    const nodeId = computeNodeId(peerId);
    this.logger.debug("handleDiscoveredPeer", {nodeId: toHex(nodeId), peerId: peerId.toString()});
    try {
      // Check if peer is not banned or disconnected
      if (this.peerRpcScores.getScoreState(peerId) !== ScoreState.Healthy) {
        return DiscoveredPeerStatus.bad_score;
      }

      const peerIdStr = peerId.toString();
      // check if peer has a cool-down period applied for reconnection. Is possible that a peer has a
      // "healthy" score but has disconnected us and we are letting the reconnection cool-down before
      // they are eligible for reconnection
      if (this.peerRpcScores.isCoolingDown(peerIdStr)) {
        return DiscoveredPeerStatus.peer_cooling_down;
      }

      // Ignore connected peers. TODO: Is this check necessary?
      if (this.isPeerConnected(peerIdStr)) {
        return DiscoveredPeerStatus.already_connected;
      }

      // ignore peers if they don't share any transport with us
      const hasTcpMatch = this.transports.includes("tcp") && multiaddrTCP;
      const hasQuicMatch = this.transports.includes("quic") && multiaddrQUIC;
      if (!hasTcpMatch && !hasQuicMatch) {
        return DiscoveredPeerStatus.transport_incompatible;
      }

      // Ignore dialing peers
      if (
        this.libp2p.services.components.connectionManager
          .getDialQueue()
          .find((pendingDial: PendingDial) => pendingDial.peerId?.equals(peerId))
      ) {
        return DiscoveredPeerStatus.already_dialing;
      }

      const forkSeq = this.config.getForkSeq(this.clock.currentSlot);

      // Should dial peer?
      const cachedPeer: CachedENR = {
        peerId,
        multiaddrTCP,
        multiaddrQUIC,
        subnets: {attnets, syncnets},
        addedUnixMs: Date.now(),
        // for pre-fulu, custodyGroups is null
        custodyGroups:
          forkSeq >= ForkSeq.fulu
            ? getCustodyGroups(this.config, nodeId, custodySubnetCount ?? this.config.CUSTODY_REQUIREMENT)
            : null,
      };

      // Only dial peer if necessary
      if (this.shouldDialPeer(cachedPeer)) {
        void this.dialPeer(cachedPeer);
        return DiscoveredPeerStatus.attempt_dial;
      }

      // Add to pending good peers with a last seen time
      this.cachedENRs.set(peerId.toString(), cachedPeer);
      const dropped = pruneSetToMax(this.cachedENRs, MAX_CACHED_ENRS);
      // If the cache was already full, count the peer as dropped
      return dropped > 0 ? DiscoveredPeerStatus.dropped : DiscoveredPeerStatus.cached;
    } catch (e) {
      this.logger.error("Error onDiscovered", {}, e as Error);
      return DiscoveredPeerStatus.error;
    }
  }

  private shouldDialPeer(peer: CachedENR): boolean {
    const forkSeq = this.config.getForkSeq(this.clock.currentSlot);
    if (forkSeq >= ForkSeq.fulu && peer.custodyGroups !== null) {
      // pre-fulu `this.custodyGroupQueries` is empty
      // starting from fulu, we need to make sure we have stable subnet sampling peers first
      // given SAMPLES_PER_SLOT = 8 and 100 peers, we have 800 custody columns from peers
      // with NUMBER_OF_CUSTODY_GROUPS = 128, we have 800 / 128 = 6.25 peers per column in average
      // it would not be hard to find TARGET_SUBNET_PEERS(6) peers per sampling columns columns and TARGET_GROUP_PEERS_PER_SUBNET(4) peers per non-sampling columns
      // after some first heartbeats, we should have no more column requested, then go with conditions of prior forks
      let hasMatchingGroup = false;
      let custodyGroupRequestCount = 0;
      for (const [group, peersToConnect] of this.custodyGroupQueries.entries()) {
        if (peersToConnect <= 0) {
          this.custodyGroupQueries.delete(group);
        } else if (peer.custodyGroups.includes(group)) {
          this.custodyGroupQueries.set(group, Math.max(0, peersToConnect - 1));
          hasMatchingGroup = true;
          custodyGroupRequestCount += peersToConnect;
        }
      }

      // if subnet sampling peers are not stable and this peer is not in the requested columns, ignore it
      if (custodyGroupRequestCount > 0 && !hasMatchingGroup) {
        this.metrics?.discovery.notDialReason.inc({reason: NotDialReason.not_contain_requested_sampling_groups});
        return false;
      }
    }

    // logics up to Deneb fork
    for (const type of [SubnetType.attnets, SubnetType.syncnets]) {
      for (const [subnet, {toUnixMs, peersToConnect}] of this.subnetRequests[type].entries()) {
        if (toUnixMs < Date.now() || peersToConnect === 0) {
          // Prune all requests so that we don't have to loop again
          // if we have low subnet peers then PeerManager will update us again with subnet + toUnixMs + peersToConnect
          this.subnetRequests[type].delete(subnet);
        } else {
          // not expired and peersToConnect > 0
          // if we have enough subnet peers, no need to dial more or we may have performance issues
          // see https://github.com/ChainSafe/lodestar/issues/5741#issuecomment-1643113577
          if (peer.subnets[type][subnet]) {
            this.subnetRequests[type].set(subnet, {toUnixMs, peersToConnect: Math.max(peersToConnect - 1, 0)});
            return true;
          }
        }
      }
    }

    // ideally we may want to leave this cheap condition at the top of the function
    // however we want to also update peersToConnect in this.subnetRequests
    // the this.subnetRequests[type] gradually has 0 subnet so this function should be cheap enough
    if (this.peersToConnect > 0) {
      return true;
    }

    this.metrics?.discovery.notDialReason.inc({reason: NotDialReason.not_contain_requested_attnet_syncnet_subnets});
    return false;
  }

  /**
   * Handles DiscoveryEvent::QueryResult
   * Peers that have been returned by discovery requests are dialed here if they are suitable.
   */
  private async dialPeer(cachedPeer: CachedENR): Promise<void> {
    // we dial a peer when:
    // - this.peersToConnect > 0
    // - or the peer subscribes to a subnet that we want
    // If this.peersToConnect is 3 while we need to dial 5 subnet peers, in that case we want this.peersToConnect
    // to be 0 instead of a negative value. The next heartbeat may increase this.peersToConnect again if some dials
    // are not successful.
    this.peersToConnect = Math.max(this.peersToConnect - 1, 0);

    const {peerId, multiaddrTCP, multiaddrQUIC} = cachedPeer;

    // Must add the multiaddrs array to the address book before dialing
    // https://github.com/libp2p/js-libp2p/blob/aec8e3d3bb1b245051b60c2a890550d262d5b062/src/index.js#L638
    const peer = await this.libp2p.peerStore.merge(peerId, {
      multiaddrs: [multiaddrQUIC, multiaddrTCP].filter(Boolean) as Multiaddr[],
    });
    if (peer.addresses.length === 0) {
      this.metrics?.discovery.notDialReason.inc({reason: NotDialReason.no_multiaddrs});
      return;
    }

    // Note: PeerDiscovery adds the multiaddrs beforehand
    const peerIdShort = prettyPrintPeerId(peerId);
    this.logger.debug("Dialing discovered peer", {
      peer: peerIdShort,
      addresses: peer.addresses.map((a) => a.multiaddr.toString()).join(", "),
    });

    this.metrics?.discovery.dialAttempts.inc();
    const timer = this.metrics?.discovery.dialTime.startTimer();

    // Note: `libp2p.dial()` is what libp2p.connectionManager autoDial calls
    // Note: You must listen to the connected events to listen for a successful conn upgrade
    try {
      await this.libp2p.dial(peerId);
      timer?.({status: "success"});
      this.logger.debug("Dialed discovered peer", {peer: peerIdShort});
    } catch (e) {
      timer?.({status: "error"});
      formatLibp2pDialError(e as Error);
      this.metrics?.discovery.dialError.inc({reason: getLibp2pError(e as Error)});
      this.logger.debug("Error dialing discovered peer", {peer: peerIdShort}, e as Error);
    }
  }

  /** Check if there is 1+ open connection with this peer */
  private isPeerConnected(peerIdStr: PeerIdStr): boolean {
    const connections = getConnectionsMap(this.libp2p).get(peerIdStr);
    return Boolean(connections?.value.some((connection) => connection.status === "open"));
  }
}

/**
 * libp2p errors with extremely noisy errors here, which are deeply nested taking 30-50 lines.
 * Some known errors:
 * ```
 * Error: The operation was aborted
 * Error: stream ended before 1 bytes became available
 * Error: Error occurred during XX handshake: Error occurred while verifying signed payload: Peer ID doesn't match libp2p public key
 * ```
 *
 * Also the error's message is not properly formatted, where the error message is indented and includes the full stack
 * ```
 * {
 *  emessage: '\n' +
 *    '    Error: stream ended before 1 bytes became available\n' +
 *    '        at /home/lion/Code/eth2.0/lodestar/node_modules/it-reader/index.js:37:9\n' +
 *    '        at runMicrotasks (<anonymous>)\n' +
 *    '        at decoder (/home/lion/Code/eth2.0/lodestar/node_modules/it-length-prefixed/src/decode.js:113:22)\n' +
 *    '        at first (/home/lion/Code/eth2.0/lodestar/node_modules/it-first/index.js:11:20)\n' +
 *    '        at Object.exports.read (/home/lion/Code/eth2.0/lodestar/node_modules/multistream-select/src/multistream.js:31:15)\n' +
 *    '        at module.exports (/home/lion/Code/eth2.0/lodestar/node_modules/multistream-select/src/select.js:21:19)\n' +
 *    '        at Upgrader._encryptOutbound (/home/lion/Code/eth2.0/lodestar/node_modules/libp2p/src/upgrader.js:397:36)\n' +
 *    '        at Upgrader.upgradeOutbound (/home/lion/Code/eth2.0/lodestar/node_modules/libp2p/src/upgrader.js:176:11)\n' +
 *    '        at ClassIsWrapper.dial (/home/lion/Code/eth2.0/lodestar/node_modules/libp2p-tcp/src/index.js:49:18)'
 * }
 * ```
 *
 * Tracking issue https://github.com/libp2p/js-libp2p/issues/996
 */
function formatLibp2pDialError(e: Error): void {
  const errorMessage = e.message.trim();
  const newlineIndex = errorMessage.indexOf("\n");
  e.message = newlineIndex !== -1 ? errorMessage.slice(0, newlineIndex) : errorMessage;

  if (
    e.message.includes("The operation was aborted") ||
    e.message.includes("stream ended before 1 bytes became available") ||
    e.message.includes("The operation was aborted")
  ) {
    e.stack = undefined;
  }
}
```

---


## peers/datastore.ts

```typescript
import {AbortOptions} from "@libp2p/interface";
import {BaseDatastore} from "datastore-core";
import {Key, KeyQuery, Pair, Query} from "interface-datastore";
import {LevelDatastore} from "#datastore-wrapper";

type MemoryItem = {
  lastAccessedMs: number;
  data: Uint8Array;
};

// biome-ignore lint/suspicious/noExplicitAny: used below (copied from upstream)
type AwaitGenerator<T, TReturn = any, TNext = any> = Generator<T, TReturn, TNext> | AsyncGenerator<T, TReturn, TNext>;

/**
 * Before libp2p 0.35, peerstore stays in memory and periodically write to db after n dirty items
 * This has a memory issue because all peer data stays in memory and loaded at startup time
 * This is written for libp2p >=0.35, we maintain the same mechanism but with bounded data structure
 * This datastore includes a memory datastore and fallback to db datastore
 * Use an in-memory datastore with last accessed time and _maxMemoryItems, on start it's empty (lazy load)
 * - get: Search in-memory datastore first, if not found search from db.
 *     - If found from db, add back to the in-memory datastore
 *     - Update lastAccessedMs
 * - put: move oldest items from memory to db if there are more than _maxMemoryItems items in memory
 *     -  update memory datastore, only update db datastore if there are at least _threshold dirty items
 *     -  Update lastAccessedMs
 */
export class Eth2PeerDataStore extends BaseDatastore {
  private _dbDatastore: LevelDatastore;
  private _memoryDatastore: Map<string, MemoryItem>;
  /** Same to PersistentPeerStore of the old libp2p implementation */
  private _dirtyItems = new Set<string>();
  /** If there are more dirty items than threshold, commit data to db */
  private _threshold: number;
  /** If there are more memory items than this, prune oldest ones from memory and move to db */
  private _maxMemoryItems: number;

  constructor(
    dbDatastore: LevelDatastore | string,
    {threshold = 5, maxMemoryItems = 50}: {threshold?: number | undefined; maxMemoryItems?: number | undefined} = {}
  ) {
    super();

    if (threshold <= 0 || maxMemoryItems <= 0) {
      throw Error(`Invalid threshold ${threshold} or maxMemoryItems ${maxMemoryItems}`);
    }
    if (threshold > maxMemoryItems) {
      throw Error(`Threshold ${threshold} should be at most maxMemoryItems ${maxMemoryItems}`);
    }

    this._dbDatastore = typeof dbDatastore === "string" ? new LevelDatastore(dbDatastore) : dbDatastore;
    this._memoryDatastore = new Map();
    this._threshold = threshold;
    this._maxMemoryItems = maxMemoryItems;
  }

  async open(): Promise<void> {
    return this._dbDatastore.open();
  }

  async close(): Promise<void> {
    return this._dbDatastore.close();
  }

  async put(key: Key, val: Uint8Array, _options?: AbortOptions): Promise<Key> {
    return this._put(key, val, false);
  }

  /**
   * Same interface to put with "fromDb" option, if this item is updated back from db
   * Move oldest items from memory data store to db if it's over this._maxMemoryItems
   */
  async _put(key: Key, val: Uint8Array, fromDb = false): Promise<Key> {
    while (this._memoryDatastore.size >= this._maxMemoryItems) {
      // it's likely this is called only 1 time
      await this.pruneMemoryDatastore();
    }

    const keyStr = key.toString();
    const memoryItem = this._memoryDatastore.get(keyStr);
    if (memoryItem) {
      // update existing
      memoryItem.lastAccessedMs = Date.now();
      memoryItem.data = val;
    } else {
      // new
      this._memoryDatastore.set(keyStr, {data: val, lastAccessedMs: Date.now()});
    }

    if (!fromDb) await this._addDirtyItem(keyStr);
    return key;
  }

  /**
   * Check memory datastore - update lastAccessedMs, then db datastore
   * If found in db datastore then update back the memory datastore
   * This throws error if not found
   * see https://github.com/ipfs/js-datastore-level/blob/38f44058dd6be858e757a1c90b8edb31590ec0bc/src/index.js#L102
   */
  async get(key: Key, options?: AbortOptions): Promise<Uint8Array> {
    const keyStr = key.toString();
    const memoryItem = this._memoryDatastore.get(keyStr);
    if (memoryItem) {
      memoryItem.lastAccessedMs = Date.now();
      return memoryItem.data;
    }

    // this throws error if not found
    const dbValue = await this._dbDatastore.get(key, options);
    // don't call this._memoryDatastore.set directly
    // we want to get through prune() logic with fromDb as true
    await this._put(key, dbValue, true);
    return dbValue;
  }

  async has(key: Key, options?: AbortOptions): Promise<boolean> {
    try {
      await this.get(key, options);
    } catch (err) {
      // this is the same to how js-datastore-level handles notFound error
      // https://github.com/ipfs/js-datastore-level/blob/38f44058dd6be858e757a1c90b8edb31590ec0bc/src/index.js#L121
      if ((err as {notFound: boolean}).notFound) return false;
      throw err;
    }
    return true;
  }

  async delete(key: Key, options?: AbortOptions): Promise<void> {
    this._memoryDatastore.delete(key.toString());
    await this._dbDatastore.delete(key, options);
  }

  async *_all(q: Query, options?: AbortOptions): AwaitGenerator<Pair> {
    for (const [key, value] of this._memoryDatastore.entries()) {
      yield {
        key: new Key(key),
        value: value.data,
      };
    }
    yield* this._dbDatastore.query(q, options);
  }

  async *_allKeys(q: KeyQuery, options?: AbortOptions): AwaitGenerator<Key> {
    for (const key of this._memoryDatastore.keys()) {
      yield new Key(key);
    }
    yield* this._dbDatastore.queryKeys(q, options);
  }

  private async _addDirtyItem(keyStr: string): Promise<void> {
    this._dirtyItems.add(keyStr);
    if (this._dirtyItems.size >= this._threshold) {
      try {
        await this._commitData();
      } catch (_e) {}
    }
  }

  private async _commitData(): Promise<void> {
    const batch = this._dbDatastore.batch();
    for (const keyStr of this._dirtyItems) {
      const memoryItem = this._memoryDatastore.get(keyStr);
      if (memoryItem) {
        batch.put(new Key(keyStr), memoryItem.data);
      }
    }
    await batch.commit();
    this._dirtyItems.clear();
  }

  /**
   * Prune from memory and move to db
   */
  private async pruneMemoryDatastore(): Promise<void> {
    let oldestAccessedMs = Date.now() + 1000;
    let oldestKey: string | undefined = undefined;
    let oldestValue: Uint8Array | undefined = undefined;

    for (const [key, value] of this._memoryDatastore) {
      if (value.lastAccessedMs < oldestAccessedMs) {
        oldestAccessedMs = value.lastAccessedMs;
        oldestKey = key;
        oldestValue = value.data;
      }
    }

    if (oldestKey && oldestValue) {
      await this._dbDatastore.put(new Key(oldestKey), oldestValue);
      this._memoryDatastore.delete(oldestKey);
    }
  }
}
```

---


## peers/score/index.ts

```typescript
export * from "./interface.js";
export * from "./score.js";
export * from "./store.js";
export * from "./utils.js";
```

---


## peers/score/interface.ts

```typescript
import {PeerId} from "@libp2p/interface";
import {GoodByeReasonCode} from "../../../constants/network.js";
import {PeerIdStr} from "../../../util/peerId.js";
import {NetworkCoreMetrics} from "../../core/metrics.js";

export type PeerRpcScoreOpts = {
  disablePeerScoring?: boolean;
};

export interface IPeerRpcScoreStore {
  getScore(peer: PeerId): number;
  getGossipScore(peer: PeerId): number;
  getScoreState(peer: PeerId): ScoreState;
  isCoolingDown(peer: PeerIdStr): boolean;
  dumpPeerScoreStats(): PeerScoreStats;
  applyAction(peer: PeerId, action: PeerAction, actionName: string): void;
  applyReconnectionCoolDown(peer: PeerIdStr, reason: GoodByeReasonCode): number;
  update(): void;
  updateGossipsubScore(peerId: PeerIdStr, newScore: number, ignore: boolean): void;
}

export interface IPeerScore {
  getScore(): number;
  getGossipScore(): number;
  isCoolingDown(): boolean;
  add(scoreDelta: number): number;
  update(): number;
  updateGossipsubScore(newScore: number, ignore: boolean): void;
  getStat(): PeerScoreStat;
  applyReconnectionCoolDown(reason: GoodByeReasonCode): number;
}

export enum ScoreState {
  /** We are content with the peers performance. We permit connections and messages. */
  Healthy = "Healthy",
  /** The peer should be disconnected. We allow re-connections if the peer is persistent */
  Disconnected = "Disconnected",
  /** The peer is banned. We disallow new connections until it's score has decayed into a tolerable threshold */
  Banned = "Banned",
}

export type PeerRpcScoreStoreModules = {
  metrics: NetworkCoreMetrics | null;
};

export type PeerScoreStats = ({peerId: PeerIdStr} & PeerScoreStat)[];

export type PeerScoreStat = {
  lodestarScore: number;
  gossipScore: number;
  ignoreNegativeGossipScore: boolean;
  score: number;
  lastUpdate: number;
};

export enum PeerAction {
  /** Immediately ban peer */
  Fatal = "Fatal",
  /**
   * Not malicious action, but it must not be tolerated
   * ~5 occurrences will get the peer banned
   */
  LowToleranceError = "LowToleranceError",
  /**
   * Negative action that can be tolerated only sometimes
   * ~10 occurrences will get the peer banned
   */
  MidToleranceError = "MidToleranceError",
  /**
   * Some error that can be tolerated multiple times
   * ~50 occurrences will get the peer banned
   */
  HighToleranceError = "HighToleranceError",
}
```

---


## peers/score/constants.ts

```typescript
import {gossipScoreThresholds} from "../../gossip/scoringParameters.js";

/** The default score for new peers */
export const DEFAULT_SCORE = 0;
/** The minimum reputation before a peer is disconnected */
export const MIN_SCORE_BEFORE_DISCONNECT = -20;
/** The minimum reputation before a peer is banned */
export const MIN_SCORE_BEFORE_BAN = -50;
// If a peer has a lodestar score below this constant all other score parts will get ignored and
// the peer will get banned regardless of the other parts.
export const MIN_LODESTAR_SCORE_BEFORE_BAN = -60.0;
/** The maximum score a peer can obtain. Update metrics.peerScore if this changes */
export const MAX_SCORE = 100;
/** The minimum score a peer can obtain. Update metrics.peerScore if this changes */
export const MIN_SCORE = -100;
/** Drop score if absolute value is below this threshold */
export const SCORE_THRESHOLD = 1;
/** The halflife of a peer's score. I.e the number of milliseconds it takes for the score to decay to half its value */
export const SCORE_HALFLIFE_MS = 10 * 60 * 1000;
export const HALFLIFE_DECAY_MS = -Math.log(2) / SCORE_HALFLIFE_MS;
/** The number of milliseconds we ban a peer for before their score begins to decay */
export const COOL_DOWN_BEFORE_DECAY_MS = 30 * 60 * 1000;
/** Limit of entries in the scores map */
export const MAX_ENTRIES = 1000;
/** Const that gets returned when no cool-down is applied */
export const NO_COOL_DOWN_APPLIED = -1;

/**
 * We weight negative gossipsub scores in such a way that they never result in a disconnect by
 * themselves. This "solves" the problem of non-decaying gossipsub scores for disconnected peers.
 */
export const GOSSIPSUB_NEGATIVE_SCORE_WEIGHT =
  (MIN_SCORE_BEFORE_DISCONNECT + 1) / gossipScoreThresholds.graylistThreshold;
export const GOSSIPSUB_POSITIVE_SCORE_WEIGHT = GOSSIPSUB_NEGATIVE_SCORE_WEIGHT;
```

---


## peers/score/score.ts

```typescript
import {GoodByeReasonCode} from "../../../constants/network.js";
import {
  COOL_DOWN_BEFORE_DECAY_MS,
  DEFAULT_SCORE,
  GOSSIPSUB_NEGATIVE_SCORE_WEIGHT,
  GOSSIPSUB_POSITIVE_SCORE_WEIGHT,
  HALFLIFE_DECAY_MS,
  MAX_SCORE,
  MIN_LODESTAR_SCORE_BEFORE_BAN,
  MIN_SCORE,
  NO_COOL_DOWN_APPLIED,
} from "./constants.js";
import {IPeerScore, PeerScoreStat, ScoreState} from "./interface.js";
import {scoreToState} from "./utils.js";

/**
 * Manage score of a peer.
 */
export class RealScore implements IPeerScore {
  private lodestarScore: number;
  private gossipScore: number;
  private ignoreNegativeGossipScore: boolean;
  /** The final score, computed from the above */
  private score: number;
  private lastUpdate: number;

  constructor() {
    this.lodestarScore = DEFAULT_SCORE;
    this.gossipScore = DEFAULT_SCORE;
    this.score = DEFAULT_SCORE;
    this.ignoreNegativeGossipScore = false;
    this.lastUpdate = Date.now();
  }

  isCoolingDown(): boolean {
    return Date.now() < this.lastUpdate;
  }

  getScore(): number {
    return this.score;
  }

  getGossipScore(): number {
    return this.gossipScore;
  }

  add(scoreDelta: number): number {
    let newScore = this.lodestarScore + scoreDelta;
    if (newScore > MAX_SCORE) newScore = MAX_SCORE;
    if (newScore < MIN_SCORE) newScore = MIN_SCORE;

    this.setLodestarScore(newScore);
    return newScore;
  }

  applyReconnectionCoolDown(reason: GoodByeReasonCode): number {
    let coolDownMin = NO_COOL_DOWN_APPLIED;
    switch (reason) {
      // let scoring system handle score decay by itself
      case GoodByeReasonCode.BANNED:
      case GoodByeReasonCode.SCORE_TOO_LOW:
        return coolDownMin;
      case GoodByeReasonCode.INBOUND_DISCONNECT:
      case GoodByeReasonCode.TOO_MANY_PEERS:
        coolDownMin = 5;
        break;
      case GoodByeReasonCode.ERROR:
      case GoodByeReasonCode.CLIENT_SHUTDOWN:
        coolDownMin = 60;
        break;
      case GoodByeReasonCode.IRRELEVANT_NETWORK:
        coolDownMin = 240;
        break;
    }
    // set banning period to time in ms in the future from now
    this.lastUpdate = Date.now() + coolDownMin * 60 * 1000;
    return coolDownMin;
  }

  /**
   * Applies time-based logic such as decay rates to the score.
   * This function should be called periodically.
   *
   * Return the new score.
   */
  update(): number {
    const nowMs = Date.now();

    // Decay the current score
    // Using exponential decay based on a constant half life.
    const sinceLastUpdateMs = nowMs - this.lastUpdate;
    // If peer was banned, lastUpdate will be in the future
    if (sinceLastUpdateMs > 0) {
      this.lastUpdate = nowMs;
      // e^(-ln(2)/HL*t)
      const decayFactor = Math.exp(HALFLIFE_DECAY_MS * sinceLastUpdateMs);
      this.setLodestarScore(this.lodestarScore * decayFactor);
    }

    return this.lodestarScore;
  }

  updateGossipsubScore(newScore: number, ignore: boolean): void {
    // we only update gossipsub if last_updated is in the past which means either the peer is
    // not banned or the BANNED_BEFORE_DECAY time is over.
    if (this.lastUpdate <= Date.now()) {
      this.gossipScore = newScore;
      this.ignoreNegativeGossipScore = ignore;
    }
  }

  getStat(): PeerScoreStat {
    return {
      lodestarScore: this.lodestarScore,
      gossipScore: this.gossipScore,
      ignoreNegativeGossipScore: this.ignoreNegativeGossipScore,
      score: this.score,
      lastUpdate: this.lastUpdate,
    };
  }

  /**
   * Updating lodestarScore should always go through this method,
   * so that we update this.score accordingly.
   */
  private setLodestarScore(newScore: number): void {
    this.lodestarScore = newScore;
    this.updateState();
  }

  /**
   * Compute the final score, ban peer if needed
   */
  private updateState(): void {
    const prevState = scoreToState(this.score);
    this.recomputeScore();
    const newState = scoreToState(this.score);

    if (prevState !== ScoreState.Banned && newState === ScoreState.Banned) {
      // ban this peer for at least BANNED_BEFORE_DECAY_MS seconds
      this.lastUpdate = Date.now() + COOL_DOWN_BEFORE_DECAY_MS;
    }
  }

  /**
   * Compute the final score
   */
  private recomputeScore(): void {
    this.score = this.lodestarScore;
    if (this.score <= MIN_LODESTAR_SCORE_BEFORE_BAN) {
      // ignore all other scores, i.e. do nothing here
      return;
    }

    if (this.gossipScore >= 0) {
      this.score += this.gossipScore * GOSSIPSUB_POSITIVE_SCORE_WEIGHT;
    } else if (!this.ignoreNegativeGossipScore) {
      this.score += this.gossipScore * GOSSIPSUB_NEGATIVE_SCORE_WEIGHT;
    }
  }
}

/** An implementation of IPeerScore for testing */
export class MaxScore implements IPeerScore {
  getScore(): number {
    return MAX_SCORE;
  }

  getGossipScore(): number {
    return DEFAULT_SCORE;
  }

  isCoolingDown(): boolean {
    return false;
  }

  add(): number {
    return DEFAULT_SCORE;
  }

  update(): number {
    return MAX_SCORE;
  }

  applyReconnectionCoolDown(_reason: GoodByeReasonCode): number {
    return NO_COOL_DOWN_APPLIED;
  }

  updateGossipsubScore(): void {}

  getStat(): PeerScoreStat {
    return {
      lodestarScore: MAX_SCORE,
      gossipScore: DEFAULT_SCORE,
      ignoreNegativeGossipScore: false,
      score: MAX_SCORE,
      lastUpdate: Date.now(),
    };
  }
}
```

---


## peers/score/store.ts

```typescript
import {PeerId} from "@libp2p/interface";
import {Logger, MapDef, pruneSetToMax} from "@lodestar/utils";
import {GoodByeReasonCode} from "../../../constants/network.js";
import {PeerIdStr} from "../../../util/peerId.js";
import {NetworkCoreMetrics} from "../../core/metrics.js";
import {prettyPrintPeerId} from "../../util.js";
import {DEFAULT_SCORE, MAX_ENTRIES, MAX_SCORE, MIN_SCORE, SCORE_THRESHOLD} from "./constants.js";
import {IPeerRpcScoreStore, IPeerScore, PeerAction, PeerRpcScoreOpts, PeerScoreStats, ScoreState} from "./interface.js";
import {MaxScore, RealScore} from "./score.js";
import {scoreToState} from "./utils.js";

const peerActionScore: Record<PeerAction, number> = {
  [PeerAction.Fatal]: -(MAX_SCORE - MIN_SCORE),
  [PeerAction.LowToleranceError]: -10,
  [PeerAction.MidToleranceError]: -5,
  [PeerAction.HighToleranceError]: -1,
};

/**
 * A peer's score (perceived potential usefulness).
 * This simplistic version consists of a global score per peer which decays to 0 over time.
 * The decay rate applies equally to positive and negative scores.
 * Peer cool-down period will be checked before dialing and will only be dialed if score is not waiting to decay
 */
export class PeerRpcScoreStore implements IPeerRpcScoreStore {
  private readonly scores: MapDef<PeerIdStr, IPeerScore>;
  private readonly metrics: NetworkCoreMetrics | null;
  private readonly logger: Logger | null;

  // TODO: Persist scores, at least BANNED status to disk

  constructor(opts: PeerRpcScoreOpts = {}, metrics: NetworkCoreMetrics | null = null, logger: Logger | null = null) {
    this.metrics = metrics;
    this.logger = logger;
    this.scores = opts.disablePeerScoring ? new MapDef(() => new MaxScore()) : new MapDef(() => new RealScore());
  }

  getScore(peer: PeerId): number {
    return this.scores.get(peer.toString())?.getScore() ?? DEFAULT_SCORE;
  }

  getGossipScore(peer: PeerId): number {
    return this.scores.get(peer.toString())?.getGossipScore() ?? DEFAULT_SCORE;
  }

  getScoreState(peer: PeerId): ScoreState {
    return scoreToState(this.getScore(peer));
  }

  isCoolingDown(peerIdStr: PeerIdStr): boolean {
    return this.scores.get(peerIdStr)?.isCoolingDown() ?? false;
  }

  dumpPeerScoreStats(): PeerScoreStats {
    return Array.from(this.scores.entries()).map(([peerId, peerScore]) => ({peerId, ...peerScore.getStat()}));
  }

  applyAction(peer: PeerId, action: PeerAction, actionName: string): void {
    const peerScore = this.scores.getOrDefault(peer.toString());
    const scoreChange = peerActionScore[action];
    const newScore = peerScore.add(scoreChange);

    this.logger?.debug("peer score adjusted", {scoreChange, newScore, peerId: prettyPrintPeerId(peer), actionName});
    this.metrics?.peersReportPeerCount.inc({reason: actionName});
  }

  /**
   * Apply a reconnection cool-down period to prevent automatic reconnection. Sets peer
   * banning period and updates gossip score to -1 so next update removes the negative
   * score
   */
  applyReconnectionCoolDown(peer: PeerIdStr, reason: GoodByeReasonCode): number {
    const peerScore = this.scores.getOrDefault(peer);
    return peerScore.applyReconnectionCoolDown(reason);
  }

  update(): void {
    // Bound size of data structures
    pruneSetToMax(this.scores, MAX_ENTRIES);

    for (const [peerIdStr, peerScore] of this.scores) {
      const newScore = peerScore.update();

      // Prune scores below threshold
      if (Math.abs(newScore) < SCORE_THRESHOLD) {
        this.scores.delete(peerIdStr);
      }
    }
  }

  updateGossipsubScore(peerId: PeerIdStr, newScore: number, ignore: boolean): void {
    const peerScore = this.scores.getOrDefault(peerId);
    peerScore.updateGossipsubScore(newScore, ignore);
  }
}
```

---


## peers/score/utils.ts

```typescript
import {negativeGossipScoreIgnoreThreshold} from "../../gossip/scoringParameters.js";
import {MIN_SCORE_BEFORE_BAN, MIN_SCORE_BEFORE_DISCONNECT} from "./constants.js";
import {IPeerRpcScoreStore, ScoreState} from "./interface.js";

export function scoreToState(score: number): ScoreState {
  if (score <= MIN_SCORE_BEFORE_BAN) return ScoreState.Banned;
  if (score <= MIN_SCORE_BEFORE_DISCONNECT) return ScoreState.Disconnected;
  return ScoreState.Healthy;
}

/**
 * Utility to update gossipsub score of connected peers
 */
export function updateGossipsubScores(
  peerRpcScores: IPeerRpcScoreStore,
  gossipsubScores: Map<string, number>,
  toIgnoreNegativePeers: number
): void {
  // sort by gossipsub score desc
  const sortedPeerIds = Array.from(gossipsubScores.keys()).sort(
    (a, b) => (gossipsubScores.get(b) ?? 0) - (gossipsubScores.get(a) ?? 0)
  );
  for (const peerId of sortedPeerIds) {
    const gossipsubScore = gossipsubScores.get(peerId);
    if (gossipsubScore !== undefined) {
      let ignore = false;
      if (gossipsubScore < 0 && gossipsubScore > negativeGossipScoreIgnoreThreshold && toIgnoreNegativePeers > 0) {
        // We ignore the negative score for the best negative peers so that their
        // gossipsub score can recover without getting disconnected.
        ignore = true;
        toIgnoreNegativePeers -= 1;
      }

      peerRpcScores.updateGossipsubScore(peerId, gossipsubScore, ignore);
    }
  }
}
```

---


## peers/utils/index.ts

```typescript
export * from "./assertPeerRelevance.js";
export * from "./getConnectedPeerIds.js";
export * from "./prioritizePeers.js";
export * from "./subnetMap.js";
```

---


## peers/utils/prioritizePeers.ts

```typescript
import type {MessageStreamDirection, PeerId} from "@libp2p/interface";
import {BitArray} from "@chainsafe/ssz";
import {ChainConfig} from "@lodestar/config";
import {ATTESTATION_SUBNET_COUNT, SYNC_COMMITTEE_SUBNET_COUNT} from "@lodestar/params";
import {CustodyIndex, Status, SubnetID, altair, phase0} from "@lodestar/types";
import {MapDef} from "@lodestar/utils";
import {shuffle} from "../../../util/shuffle.js";
import {sortBy} from "../../../util/sortBy.js";
import {NetworkCoreMetrics} from "../../core/metrics.js";
import {RequestedSubnet} from "./subnetMap.js";

/** Target number of peers we'd like to have connected to a given long-lived subnet */
const TARGET_SUBNET_PEERS = 6;

/**
 * This is for non-sampling groups only. This is a very easy number to achieve given an average of 6.25 peers per column subnet on public networks.
 * This is needed to always maintain some minimum peers on all subnets so that when we publish a block, we're sure we pubish to all column subnets.
 */
const TARGET_GROUP_PEERS_PER_SUBNET = 4;

/**
 * This is used in the pruning logic. We avoid pruning peers on sync-committees if doing so would
 * lower our peer count below this number. Instead we favour a non-uniform distribution of subnet
 * peers.
 */
const MIN_SYNC_COMMITTEE_PEERS = 2;

/**
 * Lighthouse has this value as 0. However, as monitored in Lodestar mainnet node, the max score is 0
 * and average score is -0.5 to 0 so we want this value to be a little bit more relaxed
 */
const LOW_SCORE_TO_PRUNE_IF_TOO_MANY_PEERS = -2;

/**
 * Instead of attempting to connect the exact amount necessary this will overshoot a little since the success
 * rate of outgoing connections is low, <33%. If we try to connect exactly `targetPeers - connectedPeerCount` the
 * peer count will almost always be just below targetPeers triggering constant discoveries that are not necessary
 */
const PEERS_TO_CONNECT_OVERSHOOT_FACTOR = 3;

/**
 * Keep at least 10% of outbound peers. For rationale, see https://github.com/ChainSafe/lodestar/issues/2215
 */
const OUTBOUND_PEERS_RATIO = 0.1;

const attnetsZero = BitArray.fromBitLen(ATTESTATION_SUBNET_COUNT);
const syncnetsZero = BitArray.fromBitLen(SYNC_COMMITTEE_SUBNET_COUNT);

type SubnetDiscvQuery = {subnet: SubnetID; toSlot: number; maxPeersToDiscover: number};

/**
 * A map of das custody group index to maxPeersToDiscover
 */
export type CustodyGroupQueries = Map<CustodyIndex, number>;

/**
 * Comparison of our status vs a peer's status.
 *
 * The main usage of this score is to feed into peer priorization during syncing, and especially when the node is having trouble finding data during syncing
 *
 * For network stability, we DON'T distinguish peers that are far behind us vs peers that are close to us.
 */
enum StatusScore {
  /** The peer is close to our chain */
  CLOSE_TO_US = -1,
  /** The peer is far ahead of chain */
  FAR_AHEAD = 0,
}

/**
 * In practice, this score only tracks if the peer is far ahead of us or not during syncing.
 * When the node is synced, the peer is always CLOSE_TO_US.
 */
function computeStatusScore(ours: Status, theirs: Status | null, opts: PrioritizePeersOpts): StatusScore {
  if (theirs === null) {
    return StatusScore.CLOSE_TO_US;
  }

  if (theirs.finalizedEpoch > ours.finalizedEpoch) {
    return StatusScore.FAR_AHEAD;
  }

  if (theirs.headSlot > ours.headSlot + opts.starvationThresholdSlots) {
    return StatusScore.FAR_AHEAD;
  }

  // It's dangerous to downscore peers that are far behind.
  // This means we'd be more likely to disconnect peers that are attempting to sync, which would affect network stability.
  // if (ours.headSlot > theirs.headSlot + opts.starvationThresholdSlots) {
  //   return StatusScore.FAR_BEHIND;
  // }

  return StatusScore.CLOSE_TO_US;
}

type PeerInfo = {
  id: PeerId;
  direction: MessageStreamDirection | null;
  statusScore: StatusScore;
  attnets: phase0.AttestationSubnets;
  syncnets: altair.SyncSubnets;
  samplingGroups: CustodyIndex[];
  attnetsTrueBitIndices: number[];
  syncnetsTrueBitIndices: number[];
  score: number;
};

export type PrioritizePeersOpts = {
  targetPeers: number;
  maxPeers: number;
  targetGroupPeers: number;
  status: Status;
  starved: boolean;
  starvationPruneRatio: number;
  starvationThresholdSlots: number;
  outboundPeersRatio?: number;
  targetSubnetPeers?: number;
};

export enum ExcessPeerDisconnectReason {
  LOW_SCORE = "low_score",
  NO_LONG_LIVED_SUBNET = "no_long_lived_subnet",
  TOO_GROUPED_SUBNET = "too_grouped_subnet",
  FIND_BETTER_PEERS = "find_better_peers",
}

/**
 * Prioritize which peers to disconect and which to connect. Conditions:
 * - Reach `targetPeers`
 *   - If we're starved for data, prune additional peers
 * - Don't exceed `maxPeers`
 * - Ensure there are enough peers per column subnets, attestation subnets and sync committee subnets
 * - Prioritize peers with good score
 *
 * pre-fulu samplingGroups is not used and this function returns empty custodyGroupQueries
 */
export function prioritizePeers(
  connectedPeersInfo: {
    id: PeerId;
    direction: MessageStreamDirection | null;
    status: Status | null;
    attnets: phase0.AttestationSubnets | null;
    syncnets: altair.SyncSubnets | null;
    samplingGroups: CustodyIndex[] | null;
    score: number;
  }[],
  activeAttnets: RequestedSubnet[],
  activeSyncnets: RequestedSubnet[],
  samplingGroups: CustodyIndex[] | undefined,
  opts: PrioritizePeersOpts,
  config: ChainConfig,
  metrics: NetworkCoreMetrics | null
): {
  peersToConnect: number;
  peersToDisconnect: Map<ExcessPeerDisconnectReason, PeerId[]>;
  attnetQueries: SubnetDiscvQuery[];
  syncnetQueries: SubnetDiscvQuery[];
  custodyGroupQueries: CustodyGroupQueries;
} {
  const {targetPeers, maxPeers} = opts;

  let peersToConnect = 0;
  const peersToDisconnect = new MapDef<ExcessPeerDisconnectReason, PeerId[]>(() => []);

  // Pre-compute trueBitIndexes for re-use below. Set null subnets Maps to default zero value
  const connectedPeers = connectedPeersInfo.map(
    (peer): PeerInfo => ({
      id: peer.id,
      direction: peer.direction,
      statusScore: computeStatusScore(opts.status, peer.status, opts),
      attnets: peer.attnets ?? attnetsZero,
      syncnets: peer.syncnets ?? syncnetsZero,
      samplingGroups: peer.samplingGroups ?? [],
      attnetsTrueBitIndices: peer.attnets?.getTrueBitIndexes() ?? [],
      syncnetsTrueBitIndices: peer.syncnets?.getTrueBitIndexes() ?? [],
      score: peer.score,
    })
  );

  const {attnetQueries, syncnetQueries, custodyGroupQueries, dutiesByPeer} = requestSubnetPeers(
    connectedPeers,
    activeAttnets,
    activeSyncnets,
    samplingGroups,
    opts,
    config,
    metrics
  );

  const connectedPeerCount = connectedPeers.length;

  if (connectedPeerCount < targetPeers) {
    // Need more peers.
    // Instead of attempting to connect the exact amount necessary this will overshoot a little since the success
    // rate of outgoing connections is low, <33%. If we try to connect exactly `targetPeers - connectedPeerCount` the
    // peer count will almost always be just below targetPeers triggering constant discoveries that are not necessary
    peersToConnect = Math.min(
      PEERS_TO_CONNECT_OVERSHOOT_FACTOR * (targetPeers - connectedPeerCount),
      // Never attempt to connect more peers than maxPeers even considering a low chance of dial success
      maxPeers - connectedPeerCount
    );
  } else if (connectedPeerCount > targetPeers) {
    pruneExcessPeers(connectedPeers, dutiesByPeer, activeAttnets, peersToDisconnect, opts);
  }

  return {
    peersToConnect,
    peersToDisconnect,
    attnetQueries,
    syncnetQueries,
    custodyGroupQueries,
  };
}

/**
 * If more peers are needed in attnets and syncnets and column subnets, create SubnetDiscvQuery for each subnet
 * pre-fulu samplingGroups is not used and this function returns empty custodyGroupQueries
 */
function requestSubnetPeers(
  connectedPeers: PeerInfo[],
  activeAttnets: RequestedSubnet[],
  activeSyncnets: RequestedSubnet[],
  ourSamplingGroups: CustodyIndex[] | undefined,
  opts: PrioritizePeersOpts,
  config: ChainConfig,
  metrics: NetworkCoreMetrics | null
): {
  attnetQueries: SubnetDiscvQuery[];
  syncnetQueries: SubnetDiscvQuery[];
  custodyGroupQueries: CustodyGroupQueries;
  dutiesByPeer: Map<PeerInfo, number>;
} {
  const {targetSubnetPeers = TARGET_SUBNET_PEERS} = opts;
  const attnetQueries: SubnetDiscvQuery[] = [];
  const syncnetQueries: SubnetDiscvQuery[] = [];

  // To filter out peers containing enough attnets of interest from possible disconnection
  const dutiesByPeer = new Map<PeerInfo, number>();

  // attnets, do we need queries for more peers
  if (activeAttnets.length > 0) {
    /** Map of peers per subnet, peer may be in multiple arrays */
    const peersPerSubnet = new Map<number, number>();

    for (const peer of connectedPeers) {
      const trueBitIndices = peer.attnetsTrueBitIndices;
      let dutyCount = 0;
      for (const {subnet} of activeAttnets) {
        if (trueBitIndices.includes(subnet)) {
          dutyCount += 1;
          peersPerSubnet.set(subnet, 1 + (peersPerSubnet.get(subnet) ?? 0));
        }
      }
      dutiesByPeer.set(peer, dutyCount);
    }

    for (const {subnet, toSlot} of activeAttnets) {
      const peersInSubnet = peersPerSubnet.get(subnet) ?? 0;
      if (peersInSubnet < targetSubnetPeers) {
        // We need more peers
        attnetQueries.push({subnet, toSlot, maxPeersToDiscover: targetSubnetPeers - peersInSubnet});
      }
    }
  }

  // syncnets, do we need queries for more peers
  if (activeSyncnets.length > 0) {
    /** Map of peers per subnet, peer may be in multiple arrays */
    const peersPerSubnet = new Map<number, number>();

    for (const peer of connectedPeers) {
      const trueBitIndices = peer.syncnetsTrueBitIndices;
      let dutyCount = dutiesByPeer.get(peer) ?? 0;
      for (const {subnet} of activeSyncnets) {
        if (trueBitIndices.includes(subnet)) {
          dutyCount += 1;
          peersPerSubnet.set(subnet, 1 + (peersPerSubnet.get(subnet) ?? 0));
        }
      }
      dutiesByPeer.set(peer, dutyCount);
    }

    for (const {subnet, toSlot} of activeSyncnets) {
      const peersInSubnet = peersPerSubnet.get(subnet) ?? 0;
      if (peersInSubnet < targetSubnetPeers) {
        // We need more peers
        syncnetQueries.push({subnet, toSlot, maxPeersToDiscover: targetSubnetPeers - peersInSubnet});
      }
    }
  }

  const custodyGroupQueries: CustodyGroupQueries = new Map();
  // pre-fulu
  if (ourSamplingGroups == null) {
    return {attnetQueries, syncnetQueries, custodyGroupQueries, dutiesByPeer};
  }

  // column subnets, do we need queries for more peers
  const targetGroupPeersPerSamplingGroup = opts.targetGroupPeers;
  const peersPerGroup = new Map<CustodyIndex, number>();
  for (const peer of connectedPeers) {
    const peerSamplingGroups = peer.samplingGroups;
    for (const group of peerSamplingGroups) {
      peersPerGroup.set(group, 1 + (peersPerGroup.get(group) ?? 0));
    }
  }

  const ourSamplingGroupSet = new Set(ourSamplingGroups);
  for (let groupIndex = 0; groupIndex < config.NUMBER_OF_CUSTODY_GROUPS; groupIndex++) {
    const peersInGroup = peersPerGroup.get(groupIndex) ?? 0;
    metrics?.peerCountPerSamplingGroup.set({groupIndex}, peersInGroup);
    const targetGroupPeers = ourSamplingGroupSet.has(groupIndex)
      ? targetGroupPeersPerSamplingGroup
      : TARGET_GROUP_PEERS_PER_SUBNET;
    if (peersInGroup < targetGroupPeers) {
      // We need more peers
      custodyGroupQueries.set(groupIndex, targetGroupPeers - peersInGroup);
    }
  }

  return {attnetQueries, syncnetQueries, custodyGroupQueries, dutiesByPeer};
}

/**
 * Remove excess peers back down to our target values.
 * 1. Remove peers that are not subscribed to a subnet (they have less value)
 * 2. Remove worst scoring peers
 * 3. Remove peers that we have many on any particular subnet
 *   - Only consider removing peers on subnet that has > TARGET_SUBNET_PEERS to be safe
 *   - If we have a choice, do not remove peer that would drop us below targetPeersPerAttnetSubnet
 *   - If we have a choice, do not remove peer that would drop us below MIN_SYNC_COMMITTEE_PEERS
 *
 * Although the logic looks complicated, we'd prune 5 peers max per heartbeat based on the mainnet config.
 */
function pruneExcessPeers(
  connectedPeers: PeerInfo[],
  dutiesByPeer: Map<PeerInfo, number>,
  activeAttnets: RequestedSubnet[],
  peersToDisconnect: MapDef<ExcessPeerDisconnectReason, PeerId[]>,
  opts: PrioritizePeersOpts
): void {
  const {targetPeers, targetSubnetPeers = TARGET_SUBNET_PEERS, outboundPeersRatio = OUTBOUND_PEERS_RATIO} = opts;
  const connectedPeerCount = connectedPeers.length;
  const outboundPeersTarget = Math.round(outboundPeersRatio * connectedPeerCount);

  // Count outbound peers
  let outboundPeers = 0;
  for (const peer of connectedPeers) {
    if (peer.direction === "outbound") {
      outboundPeers++;
    }
  }

  let outboundPeersEligibleForPruning = 0;

  const sortedPeers = sortPeersToPrune(connectedPeers, dutiesByPeer);

  const peersEligibleForPruning = sortedPeers
    // Then, iterate from highest score to lowest doing a manual filter for duties and outbound ratio
    .filter((peer) => {
      // Peers with duties are not eligible for pruning
      if ((dutiesByPeer.get(peer) ?? 0) > 0) {
        return false;
      }

      // Peers far ahead when we're starved for data are not eligible for pruning
      if (opts.starved && peer.statusScore === StatusScore.FAR_AHEAD) {
        return false;
      }

      // outbound peers up to OUTBOUND_PEER_RATIO sorted by highest score and not eligible for pruning
      if (peer.direction === "outbound") {
        if (outboundPeers - outboundPeersEligibleForPruning > outboundPeersTarget) {
          outboundPeersEligibleForPruning++;
        } else {
          return false;
        }
      }

      return true;
    });

  let peersToDisconnectCount = 0;
  const noLongLivedSubnetPeersToDisconnect: PeerId[] = [];

  const peersToDisconnectTarget =
    // if we're starved for data, prune additional peers
    connectedPeerCount - targetPeers + (opts.starved ? targetPeers * opts.starvationPruneRatio : 0);

  // 1. Lodestar prefers disconnecting peers that does not have long lived subnets
  // See https://github.com/ChainSafe/lodestar/issues/3940
  // peers with low score will be disconnected through heartbeat in the end
  for (const peer of peersEligibleForPruning) {
    const hasLongLivedSubnet = peer.attnetsTrueBitIndices.length > 0 || peer.syncnetsTrueBitIndices.length > 0;
    if (!hasLongLivedSubnet && peersToDisconnectCount < peersToDisconnectTarget) {
      noLongLivedSubnetPeersToDisconnect.push(peer.id);
      peersToDisconnectCount++;
    }
  }
  peersToDisconnect.set(ExcessPeerDisconnectReason.NO_LONG_LIVED_SUBNET, noLongLivedSubnetPeersToDisconnect);

  // 2. Disconnect peers that have score < LOW_SCORE_TO_PRUNE_IF_TOO_MANY_PEERS
  const badScorePeersToDisconnect: PeerId[] = [];
  for (const peer of peersEligibleForPruning) {
    if (
      peer.score < LOW_SCORE_TO_PRUNE_IF_TOO_MANY_PEERS &&
      peersToDisconnectCount < peersToDisconnectTarget &&
      !noLongLivedSubnetPeersToDisconnect.includes(peer.id)
    ) {
      badScorePeersToDisconnect.push(peer.id);
      peersToDisconnectCount++;
    }
  }
  peersToDisconnect.set(ExcessPeerDisconnectReason.LOW_SCORE, badScorePeersToDisconnect);

  // 3. Disconnect peers that are too grouped on any given subnet
  const tooGroupedPeersToDisconnect: PeerId[] = [];
  if (peersToDisconnectCount < peersToDisconnectTarget) {
    // PeerInfo array by attestation subnet
    const subnetToPeers = new MapDef<number, PeerInfo[]>(() => []);
    // number of peers per long lived sync committee
    const syncCommitteePeerCount = new MapDef<number, number>(() => 0);

    // populate the above variables
    for (const peer of connectedPeers) {
      if (noLongLivedSubnetPeersToDisconnect.includes(peer.id) || badScorePeersToDisconnect.includes(peer.id)) {
        continue;
      }
      for (const subnet of peer.attnetsTrueBitIndices) {
        subnetToPeers.getOrDefault(subnet).push(peer);
      }
      for (const subnet of peer.syncnetsTrueBitIndices) {
        syncCommitteePeerCount.set(subnet, 1 + syncCommitteePeerCount.getOrDefault(subnet));
      }
    }

    while (peersToDisconnectCount < peersToDisconnectTarget) {
      const maxPeersSubnet = findMaxPeersSubnet(subnetToPeers, targetSubnetPeers);
      // peers are NOT too grouped on any given subnet, finish this loop
      if (maxPeersSubnet === null) {
        break;
      }

      const peersOnMostGroupedSubnet = subnetToPeers.get(maxPeersSubnet);
      if (peersOnMostGroupedSubnet === undefined) {
        break;
      }

      // Find peers to remove from the current maxPeersSubnet
      const removedPeer = findPeerToRemove(
        subnetToPeers,
        syncCommitteePeerCount,
        peersOnMostGroupedSubnet,
        targetSubnetPeers,
        activeAttnets
      );

      // If we have successfully found a candidate peer to prune, prune it,
      // otherwise all peers on this subnet should not be removed.
      // In this case, we remove all peers from the pruning logic and try another subnet.
      if (removedPeer != null) {
        // recalculate variables
        removePeerFromSubnetToPeers(subnetToPeers, removedPeer);
        decreaseSynccommitteePeerCount(syncCommitteePeerCount, removedPeer.syncnetsTrueBitIndices);

        tooGroupedPeersToDisconnect.push(removedPeer.id);
        peersToDisconnectCount++;
      } else {
        // no peer to remove from the maxPeersSubnet
        // should continue with the 2nd biggest maxPeersSubnet
        subnetToPeers.delete(maxPeersSubnet);
      }
    }

    peersToDisconnect.set(ExcessPeerDisconnectReason.TOO_GROUPED_SUBNET, tooGroupedPeersToDisconnect);

    // 4. Ensure to always to prune to target peers
    // In rare case, all peers may have duties and good score but very low long lived subnet,
    // and not too grouped to any subnets, we need to always disconnect peers until it reaches targetPeers
    // because we want to keep improving peers (long lived subnets + score)
    // otherwise we'll not able to accept new peer connection to consider better peers
    // see https://github.com/ChainSafe/lodestar/issues/5198
    const remainingPeersToDisconnect: PeerId[] = [];
    for (const {id} of sortedPeers) {
      if (peersToDisconnectCount >= peersToDisconnectTarget) {
        break;
      }
      if (
        noLongLivedSubnetPeersToDisconnect.includes(id) ||
        badScorePeersToDisconnect.includes(id) ||
        tooGroupedPeersToDisconnect.includes(id)
      ) {
        continue;
      }
      remainingPeersToDisconnect.push(id);
      peersToDisconnectCount++;
    }

    peersToDisconnect.set(ExcessPeerDisconnectReason.FIND_BETTER_PEERS, remainingPeersToDisconnect);
  }
}

/**
 * Sort peers ascending, peer-0 has the most chance to prune, peer-n has the least.
 * Shuffling first to break ties.
 * prefer sorting by status score (applicable during syncing), then dutied subnets, then number of long lived subnets, then peer score
 * peer score is the last criteria since they are supposed to be in the same score range,
 * bad score peers are removed by peer manager anyway
 */
export function sortPeersToPrune(connectedPeers: PeerInfo[], dutiesByPeer: Map<PeerInfo, number>): PeerInfo[] {
  return shuffle(connectedPeers).sort((p1, p2) => {
    const dutiedSubnet1 = dutiesByPeer.get(p1) ?? 0;
    const dutiedSubnet2 = dutiesByPeer.get(p2) ?? 0;
    if (dutiedSubnet1 === dutiedSubnet2) {
      const statusScore = p1.statusScore - p2.statusScore;
      if (statusScore !== 0) {
        return statusScore;
      }
      const [longLivedSubnets1, longLivedSubnets2] = [p1, p2].map(
        (p) => p.attnetsTrueBitIndices.length + p.syncnetsTrueBitIndices.length
      );
      if (longLivedSubnets1 === longLivedSubnets2) {
        return p1.score - p2.score;
      }
      return longLivedSubnets1 - longLivedSubnets2;
    }
    return dutiedSubnet1 - dutiedSubnet2;
  });
}

/**
 * Find subnet that has the most peers and > TARGET_SUBNET_PEERS, return null if peers are not grouped
 * to any subnets.
 */
function findMaxPeersSubnet(subnetToPeers: Map<number, PeerInfo[]>, targetSubnetPeers: number): SubnetID | null {
  let maxPeersSubnet: SubnetID | null = null;
  let maxPeerCountPerSubnet = -1;

  for (const [subnet, peers] of subnetToPeers) {
    if (peers.length > targetSubnetPeers && peers.length > maxPeerCountPerSubnet) {
      maxPeersSubnet = subnet;
      maxPeerCountPerSubnet = peers.length;
    }
  }

  return maxPeersSubnet;
}

/**
 * Find peers to remove from the current maxPeersSubnet.
 * In the long term, this logic will help us gradually find peers with more long lived subnet.
 * Return null if we should not remove any peer on the most grouped subnet.
 */
function findPeerToRemove(
  subnetToPeers: Map<number, PeerInfo[]>,
  syncCommitteePeerCount: Map<number, number>,
  peersOnMostGroupedSubnet: PeerInfo[],
  targetSubnetPeers: number,
  activeAttnets: RequestedSubnet[]
): PeerInfo | null {
  const peersOnSubnet = sortBy(peersOnMostGroupedSubnet, (peer) => peer.attnetsTrueBitIndices.length);
  let removedPeer: PeerInfo | null = null;
  for (const candidatePeer of peersOnSubnet) {
    // new logic of lodestar
    const attnetIndices = candidatePeer.attnetsTrueBitIndices;
    if (attnetIndices.length > 0) {
      const requestedSubnets = activeAttnets.map((activeAttnet) => activeAttnet.subnet);
      let minAttnetCount = ATTESTATION_SUBNET_COUNT;
      // intersection of requested subnets and subnets that peer subscribes to
      for (const subnet of requestedSubnets) {
        const numSubnetPeers = subnetToPeers.get(subnet)?.length;
        if (numSubnetPeers !== undefined && numSubnetPeers < minAttnetCount && attnetIndices.includes(subnet)) {
          minAttnetCount = numSubnetPeers;
        }
      }
      // shouldn't remove this peer because it drops us below targetSubnetPeers
      if (minAttnetCount <= targetSubnetPeers) {
        continue;
      }
    }

    // same logic to lighthouse
    const syncnetIndices = candidatePeer.syncnetsTrueBitIndices;
    // The peer is subscribed to some long-lived sync-committees
    if (syncnetIndices.length > 0) {
      const minSubnetCount = Math.min(...syncnetIndices.map((subnet) => syncCommitteePeerCount.get(subnet) ?? 0));
      // If the minimum count is our target or lower, we
      // shouldn't remove this peer, because it drops us lower
      // than our target
      if (minSubnetCount <= MIN_SYNC_COMMITTEE_PEERS) {
        continue;
      }
    }

    // ok, found a peer to remove
    removedPeer = candidatePeer;
    break;
  }

  return removedPeer;
}

/**
 * Remove a peer from subnetToPeers map.
 */
function removePeerFromSubnetToPeers(subnetToPeers: Map<number, PeerInfo[]>, removedPeer: PeerInfo): void {
  for (const peers of subnetToPeers.values()) {
    const index = peers.findIndex((peer) => peer === removedPeer);
    if (index >= 0) {
      peers.splice(index, 1);
    }
  }
}

/**
 * Decrease the syncCommitteePeerCount from the specified committees set
 */
function decreaseSynccommitteePeerCount(
  syncCommitteePeerCount: MapDef<number, number>,
  committees: number[] | undefined
): void {
  if (committees) {
    for (const syncCommittee of committees) {
      syncCommitteePeerCount.set(syncCommittee, Math.max(syncCommitteePeerCount.getOrDefault(syncCommittee) - 1, 0));
    }
  }
}
```

---


## peers/utils/assertPeerRelevance.ts

```typescript
import {ForkName, isForkPostFulu} from "@lodestar/params";
import {ForkDigest, Root, Slot, Status, fulu, ssz} from "@lodestar/types";
import {toHex, toRootHex} from "@lodestar/utils";

// TODO: Why this value? (From Lighthouse)
const FUTURE_SLOT_TOLERANCE = 1;

export enum IrrelevantPeerCode {
  INCOMPATIBLE_FORKS = "IRRELEVANT_PEER_INCOMPATIBLE_FORKS",
  DIFFERENT_CLOCKS = "IRRELEVANT_PEER_DIFFERENT_CLOCKS",
  DIFFERENT_FINALIZED = "IRRELEVANT_PEER_DIFFERENT_FINALIZED",
  NO_EARLIEST_AVAILABLE_SLOT = "NO_EARLIEST_AVAILABLE_SLOT",
}

type IrrelevantPeerType =
  | {code: IrrelevantPeerCode.INCOMPATIBLE_FORKS; ours: ForkDigest; theirs: ForkDigest}
  | {code: IrrelevantPeerCode.DIFFERENT_CLOCKS; slotDiff: number}
  | {code: IrrelevantPeerCode.NO_EARLIEST_AVAILABLE_SLOT}
  | {code: IrrelevantPeerCode.DIFFERENT_FINALIZED; expectedRoot: Root; remoteRoot: Root};

/**
 * Process a `Status` message to determine if a peer is relevant to us. If the peer is
 * irrelevant the reason is returned.
 */
export function assertPeerRelevance(
  forkName: ForkName,
  remote: Status,
  local: Status,
  currentSlot: Slot
): IrrelevantPeerType | null {
  // The node is on a different network/fork
  if (!ssz.ForkDigest.equals(local.forkDigest, remote.forkDigest)) {
    return {
      code: IrrelevantPeerCode.INCOMPATIBLE_FORKS,
      ours: local.forkDigest,
      theirs: remote.forkDigest,
    };
  }

  // The remote's head is on a slot that is significantly ahead of what we consider the
  // current slot. This could be because they are using a different genesis time, or that
  // their or our system's clock is incorrect.
  const slotDiff = remote.headSlot - Math.max(currentSlot, 0);
  if (slotDiff > FUTURE_SLOT_TOLERANCE) {
    return {code: IrrelevantPeerCode.DIFFERENT_CLOCKS, slotDiff};
  }

  // The remote's finalized epoch is less than or equal to ours, but the block root is
  // different to the one in our chain. Therefore, the node is on a different chain and we
  // should not communicate with them.

  if (
    remote.finalizedEpoch <= local.finalizedEpoch &&
    !isZeroRoot(remote.finalizedRoot) &&
    !isZeroRoot(local.finalizedRoot)
  ) {
    // NOTE: due to preferring to not access chain state here, we can't check the finalized root against our history.
    // The impact of not doing check is low: peers that are behind us we can't confirm they are in the same chain as us.
    // In the worst case they will attempt to sync from us, fail and disconnect. The ENR fork check should be sufficient
    // to differentiate most peers in normal network conditions.
    const remoteRoot = remote.finalizedRoot;
    const expectedRoot = remote.finalizedEpoch === local.finalizedEpoch ? local.finalizedRoot : null;

    if (expectedRoot !== null && !ssz.Root.equals(remoteRoot, expectedRoot)) {
      return {
        code: IrrelevantPeerCode.DIFFERENT_FINALIZED,
        expectedRoot: expectedRoot, // forkChoice returns Tree BranchNode which the logger prints as {}
        remoteRoot: remoteRoot,
      };
    }
  }

  if (isForkPostFulu(forkName) && (remote as fulu.Status).earliestAvailableSlot === undefined) {
    return {
      code: IrrelevantPeerCode.NO_EARLIEST_AVAILABLE_SLOT,
    };
  }

  // Note: Accept request status finalized checkpoint in the future, we do not know if it is a true finalized root
  return null;
}

export function isZeroRoot(root: Root): boolean {
  const ZERO_ROOT = ssz.Root.defaultValue();
  return ssz.Root.equals(root, ZERO_ROOT);
}

export function renderIrrelevantPeerType(type: IrrelevantPeerType): string {
  switch (type.code) {
    case IrrelevantPeerCode.INCOMPATIBLE_FORKS:
      return `INCOMPATIBLE_FORKS ours: ${toHex(type.ours)} theirs: ${toHex(type.theirs)}`;
    case IrrelevantPeerCode.DIFFERENT_CLOCKS:
      return `DIFFERENT_CLOCKS slotDiff: ${type.slotDiff}`;
    case IrrelevantPeerCode.DIFFERENT_FINALIZED:
      return `DIFFERENT_FINALIZED root: ${toRootHex(type.remoteRoot)} expected: ${toRootHex(type.expectedRoot)}`;
    case IrrelevantPeerCode.NO_EARLIEST_AVAILABLE_SLOT:
      return "No earliestAvailableSlot announced via peer Status";
  }
}
```

---


## peers/utils/getConnectedPeerIds.ts

```typescript
import {Connection, PeerId} from "@libp2p/interface";
import {Libp2p} from "../../interface.js";
import {getConnectionsMap} from "../../util.js";

/**
 * Return peers with at least one connection in status "open"
 */
export function getConnectedPeerIds(libp2p: Libp2p): PeerId[] {
  const peerIds: PeerId[] = [];
  for (const connections of getConnectionsMap(libp2p).values()) {
    const openConnection = connections.value.find(isConnectionOpen);
    if (openConnection) {
      peerIds.push(openConnection.remotePeer);
    }
  }
  return peerIds;
}

/**
 * Efficiently check if there is at least one peer connected
 */
export function hasSomeConnectedPeer(libp2p: Libp2p): boolean {
  for (const connections of getConnectionsMap(libp2p).values()) {
    if (connections.value.some(isConnectionOpen)) {
      return true;
    }
  }
  return false;
}

function isConnectionOpen(connection: Connection): boolean {
  return connection.status === "open";
}
```

---


## peers/utils/subnetMap.ts

```typescript
import {Slot, SubnetID} from "@lodestar/types";

export type RequestedSubnet = {
  subnet: SubnetID;
  /**
   * Slot after which the network will stop maintaining a min number of peers
   * connected to `subnetId`RequestedSubnet
   */
  toSlot: Slot;
};

/**
 * Track requested subnets by `toSlot`
 */
export class SubnetMap {
  /** Map of subnets and the slot until they are needed */
  private subnets = new Map<SubnetID, Slot>();

  get size(): number {
    return this.subnets.size;
  }

  has(subnet: SubnetID): boolean {
    return this.subnets.has(subnet);
  }

  /**
   * Register requested subnets, extends toSlot if same subnet.
   **/
  request(requestedSubnet: RequestedSubnet): void {
    const {subnet, toSlot} = requestedSubnet;
    this.subnets.set(subnet, Math.max(this.subnets.get(subnet) ?? 0, toSlot));
  }

  /**
   * Get last active slot of a subnet.
   */
  getToSlot(subnet: SubnetID): Slot | undefined {
    return this.subnets.get(subnet);
  }

  isActiveAtSlot(subnet: SubnetID, slot: Slot): boolean {
    const toSlot = this.subnets.get(subnet);
    return toSlot !== undefined && toSlot >= slot; // ACTIVE: >=
  }

  /** Return subnetIds with a `toSlot` equal greater than `currentSlot` */
  getActive(currentSlot: Slot): SubnetID[] {
    const subnetIds: SubnetID[] = [];
    for (const [subnet, toSlot] of this.subnets.entries()) {
      if (toSlot >= currentSlot) {
        subnetIds.push(subnet);
      }
    }
    return subnetIds;
  }

  /** Return subnetIds with a `toSlot` equal greater than `currentSlot` */
  getActiveTtl(currentSlot: Slot): RequestedSubnet[] {
    const subnets: RequestedSubnet[] = [];
    for (const [subnet, toSlot] of this.subnets.entries()) {
      if (toSlot >= currentSlot) {
        subnets.push({subnet, toSlot});
      }
    }
    return subnets;
  }

  /** Return subnetIds with a `toSlot` less than `currentSlot`. Also deletes expired entries */
  getExpired(currentSlot: Slot): SubnetID[] {
    const subnetIds: SubnetID[] = [];
    for (const [subnet, toSlot] of this.subnets.entries()) {
      if (toSlot < currentSlot) {
        subnetIds.push(subnet);
        this.subnets.delete(subnet);
      }
    }
    return subnetIds;
  }

  getAll(): SubnetID[] {
    return Array.from(this.subnets.keys());
  }

  delete(subnet: SubnetID): void {
    this.subnets.delete(subnet);
  }
}
```

---


## peers/utils/enrSubnetsDeserialize.ts

```typescript
import {getUint8ByteToBitBooleanArray} from "@chainsafe/ssz";
import {ATTESTATION_SUBNET_COUNT, SYNC_COMMITTEE_SUBNET_COUNT} from "@lodestar/params";
import {newFilledArray} from "@lodestar/state-transition";

export const zeroAttnets = newFilledArray(ATTESTATION_SUBNET_COUNT, false);
export const zeroSyncnets = newFilledArray(SYNC_COMMITTEE_SUBNET_COUNT, false);

/**
 * Fast deserialize a BitVector, with pre-cached bool array in `getUint8ByteToBitBooleanArray()`
 *
 * Never throw a deserialization error:
 * - if bytes is too short, it will pad with zeroes
 * - if bytes is too long, it will ignore the extra values
 */
export function deserializeEnrSubnets(bytes: Uint8Array, subnetCount: number): boolean[] {
  if (subnetCount <= 8) {
    return getUint8ByteToBitBooleanArray(bytes[0] ?? 0);
  }

  let boolsArr: boolean[] = [];
  const byteCount = Math.ceil(subnetCount / 8);
  for (let i = 0; i < byteCount; i++) {
    boolsArr = boolsArr.concat(getUint8ByteToBitBooleanArray(bytes[i] ?? 0));
  }

  return boolsArr;
}
```

---

