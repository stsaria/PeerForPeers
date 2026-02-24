import logging
import os
import statistics
from threading import Event, Lock, RLock, Thread, Condition
from time import sleep
from typing import Callable, Generator
from opuslib import APPLICATION_VOIP as OPUS_APPLICATION_VOIP, Encoder as OpusEncoder, Decoder as OpusDecoder
import sounddevice as sd
from numpy import ndarray
from enum import auto as a

from manager.CustomFuncs import CustomFunc, CustomFuncs
from src.app.model.Node import NodeForRelay, Relay
from src.manager.ReliableSessionIds import ReliableSessionIds
from src.model.NodeIdentify import NodeIdentify
from src.manager.AddrToEd25519PubKeys import AddrToEd25519PubKeys
from src.manager.WaitingResponses import WaitingResponses
from src.model.WaitingResponse import WAITING_RESPONSE_KEY, WaitingResponse
from src.protocol.Protocol import *
from src.protocol.ProgramProtocol import *
from src.app.protocol.Protocol import *
from src.app.protocol.ProgramProtocol import *
from src.model.NetConfig import SecureNetConfig
from src.util.ed25519 import Ed25519PrivateKey
from src.core.ExtendedNet import ExtendedNet
from src.core.SecureNet import SecureNet
from src.core.ReliableNetController import ReliableNetController
from src.core.PrivateSecureNet import PrivateSecureNet
from src.model.NodeIdentify import NodeIdentify
from src.util import bytesSplitter, ed25519, metaPro
from src.util.bytesCoverter import *
from src.util.gene import getGen
from util.Result import Result

logger = logging.getLogger(__name__)

class DirectApp:
    def __init__(self, netConfig:SecureNetConfig) -> None:
        self._ed25519PivKey:Ed25519PrivateKey = netConfig.ed25519PrivateKey
        self._extendedNet:ExtendedNet = ExtendedNet(netConfig)
        self._secureNet:SecureNet = SecureNet.getShareObj(self._extendedNet)
        self._secureNet.init(netConfig.ed25519PrivateKey)
        self._reliableNetCont:ReliableNetController = ReliableNetController(self._extendedNet, netConfig.ed25519PrivateKey)
        self._privateSecureNet:PrivateSecureNet = PrivateSecureNet.getShareObj(self._extendedNet)
    
        self._invitedNodeAddrs:list[tuple[str, int]] = []
        self._nodes:dict[str, NodeIdentify] = {}
        self._nodesLock:Lock = Lock()

        self._relayRoutes:dict[bytes, Relay] = {}
        self._relayGens:dict[bytes, list[Generator[bytes, bytes, None]]] = {}
        self._myRelayInfos:dict[bytes, tuple[DirectAppReleyRouteType, NodeIdentify, bytes]] = {}
        self._relaysCond:Condition = Condition(RLock())

        self._stop = Event()
    
        logger.debug("initialized.")
    
    class CreateNetworkResult(Result):
        ALREADY_CREATED = a()
    def createNetwork(self) -> tuple[CreateNetworkResult, tuple[Ed25519PrivateKey, bytes] | None]:
        if self._privateSecureNet != None:
            logger.warning("network already created.")
            return (self.CreateNetworkResult.ALREADY_CREATED, None)
        sharedEd25519PrivateKey = ed25519.generatePivKey()
        sharedSecret = os.urandom(ANY_SECRET_SIZE)
        
        self._privateSecureNet:PrivateSecureNet = PrivateSecureNet.getShareObj(self._extendedNet)
        self._privateSecureNet.init(
            self._ed25519PivKey,
            sharedEd25519PrivateKey,
            sharedSecret
        )
        logger.info("network created.")
        return (self.CreateNetworkResult.SUCCESS, (sharedEd25519PrivateKey, sharedSecret))
    
    class InviteForDirectAppResult(Result):
        PING_FAILED = a()
        OVER_MAX_NODES = a()
    def inviteForDirectApp(self, nodeIdentify:NodeIdentify, directAppPort:int) -> InviteForDirectAppResult:
        if self._secureNet.ping(nodeIdentify) == None:
            logger.warning("cannot invite node. (ping failed)")
            return self.InviteForDirectAppResult.PING_FAILED
        with self._nodesLock:
            if len(self._nodes)+len(self._invitedNodeAddrs) >= DIRECT_APP_MAX_NODES:
                logger.warning("cannot invite node. (over max nodes)")
                return self.InviteForDirectAppResult.OVER_MAX_NODES
            self._invitedNodeAddrs.append((nodeIdentify.ip, nodeIdentify.port))
        sharedSecret, sharedEd25519PrivateKeyB = self._privateSecureNet.getSecrets()
        self._secureNet.sendToSecure(
            AppFlag.DIRECT
            +AppModeFlag.INVITE_FOR_DIRECT_APP
            +sharedSecret
            +sharedEd25519PrivateKeyB,
            nodeIdentify
        )
        return self.InviteForDirectAppResult.SUCCESS
    
    def _informNewNodeToOther(self, newNodeIdentify:NodeIdentify) -> None:
        with self._nodesLock:
            signData = (
                stob(newNodeIdentify.ip, GlobalAppElementSize.IP, STR_ENCODING)
                +itob(newNodeIdentify.port, GlobalAppElementSize.PORT)
                +newNodeIdentify.ed25519PublicKey.public_bytes_raw()
            )
            signed = ed25519.sign(signData,self._ed25519PivKey)
            for addr, nI in self._nodes.items():
                if addr == (newNodeIdentify.ip, newNodeIdentify.port):
                    continue
                self._privateSecureNet.sendToSecure(
                    (
                        AppFlag.DIRECT
                        +AppModeFlag.INFORM_NEW_NODE
                        +signed
                        +signData
                    ),
                    nI
                )
    
    def _broadcastSecureSyncronized(self, data:bytes) -> None:
        for nI in self._nodes.values():
            self._privateSecureNet.sendToSecure(
                data,
                nI
            )
    
    def _broadcastSecure(self, data:bytes) -> None:
        with self._nodesLock:
            self._broadcastSecureSyncronized(data)
    
    class _HelloResult(Result):
        LOW_LAYER_HELLO_FAILED = a()
        RESP_HELLO_TIME_OUT = a()
        OVER_MAX_NODES = a()
        UNKNOWN = a()
    def _hello(self, nodeIdentify:NodeIdentify) -> _HelloResult:
        if not self._privateSecureNet.hello(nodeIdentify):
            return self._HelloResult.LOW_LAYER_HELLO_FAILED
        sid = ReliableSessionIds.issueTicket()
        waitingResponse = WaitingResponse(
            nodeIdentify,
            self,
            AppModeFlag.RESP_HELLO,
            otherInfoInKey=sid
        )
        WaitingResponses.addKey(waitingResponse)
        self._privateSecureNet.sendToSecure(
            (
                AppFlag.DIRECT
                +AppModeFlag.HELLO
                +sid
            ),
            nodeIdentify
        )
        if (r := WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC)) == None:
            WaitingResponses.delete(waitingResponse)
            return self._HelloResult.RESP_HELLO_TIME_OUT
        WaitingResponses.delete(waitingResponse)
        return {
            StatusForHelloForApp.SUCCESS:self._HelloResult.SUCCESS,
            StatusForHelloForApp.OVER_MAX_NODES:self._HelloResult.OVER_MAX_NODES,
            StatusForHelloForApp.UNKNOWN:self._HelloResult.UNKNOWN
        }.get(r, self._HelloResult.UNKNOWN)
    
    class JoinNetworkResult(Result):
        LOW_LAYER_HELLO_FAILED = a()
        RESP_HELLO_TIME_OUT = a()
        UNKNOWN = a()
    def joinNetwork(self, bootstrapNodeIdentify:NodeIdentify, sharedEd25519PrivateKey:Ed25519PrivateKey, sharedSecret:bytes) -> JoinNetworkResult:
        self._privateSecureNet:PrivateSecureNet = PrivateSecureNet.getShareObj(self._extendedNet)
        self._privateSecureNet.init(
            self._ed25519PivKey,
            sharedEd25519PrivateKey,
            sharedSecret
        )
        if (r := self._hello(bootstrapNodeIdentify)) != self._HelloResult.SUCCESS:
            logger.warning("failed to join network. (cannot hello bootstrap node)")
            return r
        with self._nodesLock:
            self._getNodesSyncronized(bootstrapNodeIdentify)
        logger.info("joined network.")
        return r
    
    class GetNodesSyncronizedResult(Result):
        RESP_GET_NODES_TIME_OUT = a()
        DIRECT_APP_MAX_NODES_EXCEEDED = a()
    def _getNodesSyncronized(self, nodeIdentify:NodeIdentify) -> GetNodesSyncronizedResult:
        sid = ReliableSessionIds.issueTicket()
        waitingResponse = WaitingResponse(
            nodeIdentify=nodeIdentify,
            waitingInst=self,
            waitingType=AppModeFlag.RESP_GET_NODES,
            otherInfoInKey=sid
        )
        WaitingResponses.addKey(waitingResponse)
        self._privateSecureNet.sendToSecure(
            AppFlag.DIRECT
            +AppModeFlag.GET_NODES
            +sid,
            nodeIdentify
        )
        if (r := WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC)) == None:
            WaitingResponses.delete(waitingResponse)
            return self.GetNodesSyncronizedResult.RESP_GET_NODES_TIME_OUT
        WaitingResponses.delete(waitingResponse)
        size = r
        gen = self._reliableNetCont.recvFor(
            sid,
            size,
            nodeIdentify.ed25519PublicKey
        )
        self._secureNet.sendToSecure(
            AppFlag.DIRECT
            +AppModeFlag.START_SEND_REQ
            +sid,
            nodeIdentify
        )
        nodes = []
        for data in gen:
            cache += data
            while len(cache) >= (
                GlobalAppElementSize.IP
                +GlobalAppElementSize.PORT
                +GlobalAppElementSize.ED25519_PUBLIC_KEY
            ):
                ipStrB, portB, ed25519PubKeyB, cache = bytesSplitter.split(
                    cache,
                    GlobalAppElementSize.IP,
                    GlobalAppElementSize.PORT,
                    GlobalAppElementSize.ED25519_PUBLIC_KEY,
                    includeRest=True
                )
                ip = btos(ipStrB, STR_ENCODING)
                port = btoi(portB, ENDIAN)
                if ip in self._nodes.keys():
                    logger.debug(f"node {ip} already exists.")
                    continue
                nI = NodeIdentify(
                    ip=ip,
                    port=port,
                    ed25519PublicKey=ed25519.getPubKeyByPubKeyBytes(ed25519PubKeyB)
                )
                nodes.append(nI)
        diff:list[NodeIdentify] = list(set(nodes) - set(list(self._nodes.values())))
        if len(self._nodes)+len(diff) > DIRECT_APP_MAX_NODES:
            return self.GetNodesSyncronizedResult.DIRECT_APP_MAX_NODES_EXCEEDED
        for nI in diff:
            if self._hello(nI) == StatusForHelloForApp.SUCCESS:
                self._nodes[(nI.ip, nI.port)] = nI
        logger.debug(f"collected {len(nodes)} nodes.")
        return self.GetNodesSyncronizedResult.SUCCESS

    def _relaySender(self, routeId:bytes, gen:Generator[bytes, None, None]) -> None:
        for d in gen:
            with self._relaysCond:
                firstNode = self._myRelayInfos[routeId][1]
            self._privateSecureNet.sendToSecure(
                itob(AppFlag.DIRECT, DirectAppElementSize.APP_FLAG)
                +itob(AppModeFlag.MAIN_DATA_RELAY_ROUTE, DirectAppElementSize.MODE_FLAG)
                +routeId
                +d,
                firstNode
            )

    def _activateRelayRoute(self, routeType:DirectAppReleyRouteType, otherInfo:bytes, routeId:bytes|None = None) -> bytes:
        with self._nodesLock:
            sortedNodes = CustomFuncs.get(CustomFunc.GET_SORTED_RELAY_ROUTES)(
                [
                    NodeForRelay(
                        ip=nI.ip,
                        port=nI.port,
                        ed25519PublicKey=nI.ed25519PublicKey,
                        pingDelay=statistics.median([self._privateSecureNet.ping(nI) for _ in range(PING_WINDOW)]),
                    ) for nI in self._nodes.values()
                ]
            )
            nodeEd25519PubKeysB = b"".join(
                [
                    (
                        stob(nForR.ed25519PublicKey, GlobalAppElementSize.ED25519_PUBLIC_KEY, STR_ENCODING)
                    ) for nForR in sortedNodes
                ]
            )
            self._broadcastSecureSyncronized(
                itob(AppFlag.DIRECT, DirectAppElementSize.APP_FLAG)
                +itob(AppModeFlag.ACTIVATE_RELAY_ROUTE, DirectAppElementSize.MODE_FLAG)
                +(routeId := (routeId or os.urandom(ANY_SESSION_ID_SIZE)))
                +itob(routeType, DirectAppElementSize.RELAY_ROUTE_TYPE)
                +itob(len(sortedNodes), GlobalAppElementSize.NODES_SIZE)
                +nodeEd25519PubKeysB
                +otherInfo
            )
            with self._relaysCond:
                self._myRelayInfos[routeId] = (routeType, sortedNodes[0])
        return routeId

    def _makeRelayRoute(self, routeType:DirectAppReleyRouteType, otherInfo:bytes) -> Generator[bytes, None, None]:
        gen = getGen()
        routeId = self._activateRelayRoute(routeType, otherInfo)
        Thread(
            target=self._relaySender,
            args=(routeId,),
            daemon=True
        ).start()
        return gen

    def keepSendingVoice(self, stop:Event) -> Generator[bool, None, None]:
        # yield am i speaking now every DIRECT_VOICE_SAMPLE_SEC seconds
        gen = self._makeRelayRoute(DirectAppReleyRouteType.VOICE, (
            itob(DIRECT_VOICE_SAMPLING_RATE, DirectAppElementSize.VOICE_SAMPLING_RATE)
            +itob(int(DIRECT_VOICE_SAMPLE_SEC*1000), DirectAppElementSize.VOICE_SAMPLE_MILLI_SEC)
            +itob(DIRECT_VOICE_CHANNELS, DirectAppElementSize.VOICE_CHANNELS)
        ))
        encoder = OpusEncoder(DIRECT_VOICE_SAMPLING_RATE, DIRECT_VOICE_CHANNELS, OPUS_APPLICATION_VOIP)
        encoder._set_dtx(1)
        while not stop.is_set():
            sd.default.device = DIRECT_VOICE_DEVICE_DEFAULT
            rVoice = sd.rec(
                frames=int(DIRECT_VOICE_SAMPLING_RATE*DIRECT_VOICE_SAMPLE_SEC),
                samplerate=DIRECT_VOICE_SAMPLING_RATE,
                channels=DIRECT_VOICE_CHANNELS,
                dtype=DIRECT_VOICE_DATA_TYPE
            )
            sd.wait()
            encodedVoice = encoder.encode(rVoice.tobytes(), int(DIRECT_VOICE_SAMPLING_RATE*DIRECT_VOICE_SAMPLE_SEC))
            gen.send(encodedVoice)
            yield len(encodedVoice) > DIRECT_VOICE_NOT_SPEAKING_BYTES_THRESHOLD
    
    def keepGettingActivatedVoiceRoute(self, stop:Event) -> Generator[tuple[bytes, Relay], None, None]:
        previous = {}.keys()
        with self._relaysCond:
            while not stop.is_set():
                self._relaysCond.wait()
                keys = self._relayRoutes.keys()
                if (r := list(keys - previous)):
                    yield r[0], self._relayRoutes[r[0]]
                elif (r := list(previous - keys)):
                    yield r[0], self._relayRoutes[r[0]]
                previous = keys
    
    def listenByRoute(self, routeId:bytes) -> Generator[bytes, None, None] | None:
        gen = getGen()
        with self._relaysCond:
            if not routeId in self._relayRoutes.keys():
                return
            self._relayGens[routeId].append(gen)
        return gen

    def stopListenByRoute(self, routeId:bytes, gen:Generator[bytes, None, None]) -> None:
        with self._relaysCond:
            if not routeId in self._relayRoutes.keys():
                return
            try:
                self._relayGens[routeId].remove(gen)
            except ValueError:
                pass

    # end methods for public use

    def _recvHello(self, addr:tuple[str, int]) -> None:
        with self._nodesLock:
            if not addr in self._invitedNodeAddrs:
                return
            self._invitedNodeAddrs.remove(addr)
        if (ed25519PubKey := AddrToEd25519PubKeys.get(addr)) == None:
            return
        nI = NodeIdentify(
            ip=addr[0],
            port=addr[1],
            ed25519PublicKey=ed25519PubKey
        )
        if len(self._nodes) >= DIRECT_APP_MAX_NODES:
            self._privateSecureNet.sendToSecure(
                AppFlag.DIRECT
                +AppModeFlag.RESP_HELLO
                +itob(StatusForHello.OVER_MAX_NODES, DirectAppElementSize.STATUS_FOR_HELLO),
                nI
            )
            return
        with self._nodesLock:
            if addr[0] in self._nodes.keys():
                return
            self._privateSecureNet.sendToSecure(
                AppFlag.DIRECT
                +AppModeFlag.RESP_HELLO
                +itob(StatusForHelloForApp.SUCCESS, DirectAppElementSize.STATUS_FOR_HELLO),
                nI
            )
            self._nodes[addr] = nI
        self._informNewNodeToOther(nI)
        logger.debug(f"added node {addr}.")
    
    def _recvRespHello(self, mD:bytes, addr:tuple[str, int]) -> None:
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, AppModeFlag.RESP_HELLO, None)
        
        if not WaitingResponses.containsKey(key):
            return
        statusB = bytesSplitter.split(
            mD,
            DirectAppElementSize.STATUS_FOR_HELLO,
        )
        try:
            status = StatusForHelloForApp(btoi(statusB, ENDIAN))
        except ValueError:
            WaitingResponses.updateValue(key, StatusForHelloForApp.UNKNOWN)
            return
        WaitingResponses.updateValue(key, status)
    
    def _recvInformNewNode(self, mD:bytes, addr:tuple[str, int]) -> None:
        ipB, portB, ed25519PubKeyB = bytesSplitter.split(
            mD,
            GlobalAppElementSize.IP,
            GlobalAppElementSize.PORT,
            GlobalAppElementSize.ED25519_PUBLIC_KEY
        )
        nI = NodeIdentify(
            ip=btos(ipB, STR_ENCODING),
            port=btoi(portB, ENDIAN),
            ed25519PublicKey=ed25519.getPubKeyByPubKeyBytes(ed25519PubKeyB)
        )
        addr = (nI.ip, nI.port)
        with self._nodesLock:
            if addr in self._nodes.keys():
                return
            self._nodes[addr] = nI
        logger.debug(f"added node {addr} from INFORM_NEW_NODE.")
    
    def _recvGetNodes(self, mD:bytes, addr:tuple[str, int]) -> None:
        sid = bytesSplitter.split(
            mD,
            ReliablePacketElementSize.SESSION_ID
        )[0]
        with self._nodesLock:
            nodeIdentifyBytes = (
                b"".join(
                    [   
                        (
                            stob(nI.ip, GlobalAppElementSize.IP, STR_ENCODING)
                            +itob(nI.port, GlobalAppElementSize.PORT)
                            +nI.ed25519PublicKey.public_bytes_raw()
                        ) for nI in self._nodes.values()
                    ]
                )
            )
        size = len(nodeIdentifyBytes)
        waitingResponse = WaitingResponse(
            nodeIdentify=NodeIdentify(
                ip=addr[0],
                port=addr[1],
                ed25519PublicKey=AddrToEd25519PubKeys.get(addr)
            ),
            waitingInst=self,
            waitingType=AppModeFlag.START_SEND_REQ,
            otherInfoInKey=sid
        )
        WaitingResponses.addKey(waitingResponse)
        self._privateSecureNet.sendToSecure(
            AppFlag.DIRECT
            +AppModeFlag.RESP_GET_NODES
            +sid
            +itob(size, GlobalAppElementSize.NODES_SIZE),
            addr
        )
        if WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC) == None:
            WaitingResponses.delete(waitingResponse)
            return
        WaitingResponses.delete(waitingResponse)
        gen = getGen()
        gen.send(nodeIdentifyBytes)
        self._reliableNetCont.send(waitingResponse.nodeIdentify, sid, gen)
    
    def _recvRespGetNodes(self, mD:bytes, addr:tuple[str, int]) -> None:
        sid, size = bytesSplitter.split(
            mD,
            ReliablePacketElementSize.SESSION_ID,
            DirectAppElementSize.NODES_SIZE
        )
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, AppModeFlag.RESP_GET_NODES, sid)
        if not WaitingResponses.containsKey(key):
            logger.warning(f"WaitingResponses does not contain key for {addr}")
            return
        WaitingResponses.updateValue(key, size)
    
    def _recvStartSendReq(self, mD:bytes, addr:tuple[str, int]) -> None:
        logger.debug(f"from {addr}")
        sid = bytesSplitter.split(
            mD,
            ReliablePacketElementSize.SESSION_ID
        )[0]
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, AppModeFlag.START_SEND_REQ, sid)
        if not WaitingResponses.containsKey(key):
            logger.warning(f"WaitingResponses does not contain key for {addr}")
            return
        WaitingResponses.updateValue(key, mD)
    
    def _recvActivateRelayRoute(self, mD:bytes, addr:tuple[str, int]) -> None:
        routeId, routeTypeB, nodesLenB, mD = bytesSplitter.split(
            mD,
            ANY_SESSION_ID_SIZE,
            DirectAppElementSize.RELAY_ROUTE_TYPE,
            DirectAppElementSize.NODES_SIZE,
            includeRest=True
        )
        try:
            routeType = DirectAppReleyRouteType(btoi(routeTypeB, ENDIAN))
        except ValueError:
            routeType = DirectAppReleyRouteType.UNKNOWN
        nodesLen = btoi(nodesLenB, ENDIAN)
        pubs, mD = bytesSplitter.split(
            mD,
            GlobalAppElementSize.ED25519_PUBLIC_KEY*nodesLen,
            includeRest=True
        )
        nodeEd25519PubKeysBs = [pubs[nodesLen*i:nodesLen*(i+1)] for i in range(nodesLen)]
        myPubKeyB = self._ed25519PivKey.public_key().public_bytes_raw()
        if not myPubKeyB in nodeEd25519PubKeysBs:
            return
        i = nodeEd25519PubKeysBs.index(myPubKeyB)
        recvNode = NodeIdentify(
            ip=addr[0],
            port=addr[1],
            ed25519PublicKey=AddrToEd25519PubKeys.get(addr)
        ) if i == 0 else NodeIdentify(
            ip=(addr := AddrToEd25519PubKeys.getAddrByPublicKeyBytes(nodeEd25519PubKeysBs[i-1]))[0],
            port=addr[1],
            ed25519PublicKey=ed25519.getPubKeyByPubKeyBytes(nodeEd25519PubKeysBs[i-1])
        )
        sendNode = None if i < len(nodeEd25519PubKeysBs)+1 else NodeIdentify(
            ip=(addr := AddrToEd25519PubKeys.getAddrByPublicKeyBytes(nodeEd25519PubKeysBs[i+1]))[0],
            port=addr[1],
            ed25519PublicKey=ed25519.getPubKeyByPubKeyBytes(nodeEd25519PubKeysBs[i+1])
        )
        rootNode = NodeIdentify(
            ip=addr[0],
            port=addr[1],
            ed25519PublicKey=AddrToEd25519PubKeys.get(addr)
        )
        with self._relaysCond:
            if r := self._relayRoutes.get(routeId):
                if r.rootNode.ip != addr[0] or r.rootNode.port != addr[1]:
                    return
            else:
                self._relayGens[routeId] = []
            self._relayRoutes[routeId] = Relay(
                rootNode=rootNode,
                recvNode=recvNode,
                sendNode=sendNode,
                routeType=routeType
            )
            self._relaysCond.notify_all()
    
    def _recvMainDataRelayRoute(self, mD:bytes, addr:tuple[str, int]) -> None:
        routeId, d = bytesSplitter.split(
            mD,
            ANY_SESSION_ID_SIZE,
            includeRest=True
        )
        with self._relaysCond:
            if not routeId in self._relayRoutes.keys():
                return
            r = self._relayRoutes[routeId]
            n = r.recvNode or r.rootNode
            if addr[0] != n.ip or addr[0] != n.port:
                return
            for g in self._relayGens[routeId]:
                g.send(d)

    
    def _recv(self) -> None:
        logger.debug("receiving packets...")
        for data, addr in self._privateSecureNet.recv():
            if len(data) < PrivateSecurePacketElementSize.PACKET_FLAG+PrivateSecurePacketElementSize.MODE_FLAG:
                continue
            aFlag, mFlag, mainData = bytesSplitter.split(
                data+b"\x00",
                GlobalAppElementSize.APP_FLAG,
                GlobalAppElementSize.MODE_FLAG,
                includeRest=True
            )
            mainData = mainData[:-1]
            if btoi(aFlag, ENDIAN) != AppFlag.GLOBAL.value:
                continue
            try:
                mFlag = AppModeFlag(btoi(mFlag, ENDIAN))
            except ValueError:
                continue

            if not CustomFuncs.get(CustomFunc.WILL_PASS_PACKET_FOR_DIRECT_APP)(addr, aFlag, mFlag, mainData):
                continue

            if mFlag == AppModeFlag.HELLO:
                target, args = self._recvHello, (addr,)
            elif mFlag == AppModeFlag.RESP_HELLO:
                target, args = self._recvRespHello, (mainData, addr)
            
            with self._nodesLock:
                contains = addr in self._nodes
            if contains:
                match mFlag:
                    case AppModeFlag.GET_NODES:
                        target, args = self._recvGetNodes, (mainData, addr)
                    case AppModeFlag.RESP_GET_NODES:
                        target, args = self._recvRespGetNodes, (mainData, addr)
                    case AppModeFlag.START_SEND_REQ:
                        target, args = self._recvStartSendReq, (mainData, addr)
                    case AppModeFlag.INFORM_NEW_NODE:
                        target, args = self._recvInformNewNode, (mainData, addr)
                    case AppModeFlag.ACTIVATE_RELAY_ROUTE:
                        target, args = self._recvActivateRelayRoute, (mainData, addr)
                    case AppModeFlag.MAIN_DATA_RELAY_ROUTE:
                        target, args = self._recvMainDataRelayRoute, (mainData, addr)
                    
            Thread(target=target, args=args, daemon=True).start()
    
    def _sync(self) -> None:
        logger.info("synchronization started.")
        while True:
            with self._nodesLock:
                nodes = list(self._nodes.values())
            for nI in nodes:
                self._getNodesSyncronized(nI)
            sleep(SyncIntervalSec.DIRECT)
    
    def _pingAndRemoveNode(self, nI:NodeIdentify, c:Condition, r:list[bool], i:int) -> None:
        if self._privateSecureNet.ping(nI) == None:
            with self._nodesLock:
                if (nI.ip, nI.port) in self._nodes.keys():
                    self._nodes.pop((nI.ip, nI.port))
                    logger.info(f"removed node {(nI.ip, nI.port)} (ping timeout).")
            with c:
                r[i] = True
                c.notify_all()
    
    def _pinger(self) -> None:
        logger.info("pinger started.")
        while True:
            with self._nodesLock:
                nodes = list(self._nodes.values())
            c = Condition(Lock())
            r = []
            for nI in nodes:
                with c:
                    r.append(False)
                    Thread(target=self._pingAndRemoveNode, args=(nI, c, r, len(r)-1), daemon=True).start()
            for _ in range(len(r)):
                with c:
                    c.wait()
            if any(r):
                with self._relaysCond:
                    for r, (rT, _, oI) in self._myRelayInfos:
                        self._activateRelayRoute(rT, oI, routeId=r)
            sleep(PingIntervalSec.DIRECT)
    
    def start(self) -> None:
        Thread(target=self._recv, daemon=True).start()
        Thread(target=self._sync, daemon=True).start()
        Thread(target=self._pinger, daemon=True).start()
        logger.info("DirectApp started.")
    
    def _close(self) -> None:
        self._secureNet.close()
        self._privateSecureNet.close()
        self._extendedNet.close()
    
    def stop(self) -> None:
        self._stop.set()
        self._reliableNetCont.stop()
        self._close()
