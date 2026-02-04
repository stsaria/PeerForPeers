import logging
import os
import statistics
from threading import Lock, Thread
from time import sleep
from typing import Callable, Generator

from src.app.model.Node import NodeForRelay, RelayRoute
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

logger = logging.getLogger(__name__)

class DirectApp:
    def __init__(self, netConfig:SecureNetConfig) -> None:
        self._ed25519PivKey:Ed25519PrivateKey = netConfig.ed25519PrivateKey
        self._extendedNet:ExtendedNet = ExtendedNet(netConfig)
        self._secureNet:SecureNet = SecureNet.getShareObj(self._extendedNet)
        self._secureNet.init(netConfig.ed25519PrivateKey)
        self._reliableNet:ReliableNetController = ReliableNetController(self._extendedNet, netConfig.ed25519PrivateKey)
        self._privateSecureNet:PrivateSecureNet = None
    

        self._nodes:dict[str, NodeIdentify] = {}
        self._nodesLock:Lock = Lock()

        self._relayRoutes:dict[tuple[bytes, bytes], RelayRoute] = {}
        self._relayRoutesLock:Lock = Lock()

        self._getSortedRelayRoutesFunc:Callable[[list[NodeForRelay]], list[NodeForRelay]] = lambda nodes: nodes
    
        logger.debug("initialized.")
    
    def setGetSortedRelayRoutesFunc(self, code:str) -> bool:
        try:
            self._getSortedRelayRoutesFunc = metaPro.getFuncByCodeAndName(code, GET_SORTED_RELAY_ROUTES_FUNC_NAME)
            logger.debug("getSortedRelayRoutes function set successfully.")
            return True
        except Exception:
            logger.error(f"Couldn't set getSortedRelayRoutes function. code=\n{code}", exc_info=True)
            return False
    
    def createNetwork(self) -> tuple[Ed25519PrivateKey, bytes] | None:
        if self._privateSecureNet != None:
            logger.warning("network already created.")
            return
        sharedEd25519PrivateKey = ed25519.generatePivKey()
        sharedSecret = os.urandom(ANY_SECRET_SIZE)
        
        self._privateSecureNet:PrivateSecureNet = PrivateSecureNet.getShareObj(self._extendedNet)
        self._privateSecureNet.init(
            self._ed25519PivKey,
            sharedEd25519PrivateKey,
            sharedSecret
        )
        logger.info("network created.")
    
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
    
    def _hello(self, nodeIdentify:NodeIdentify) -> StatusForJoinNetwork:
        if not self._privateSecureNet.hello(nodeIdentify):
            return StatusForJoinNetwork.PROTOCOL_HELLO_FAIL
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
        if StatusForJoinNetwork.SUCCESS != (r := WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC)):
            WaitingResponses.delete(waitingResponse)
            return r
        WaitingResponses.delete(waitingResponse)
        return StatusForJoinNetwork.SUCCESS
    
    def joinNetwork(self, bootstrapNodeIdentify:NodeIdentify, sharedEd25519PrivateKey:Ed25519PrivateKey, sharedSecret:bytes) -> StatusForJoinNetwork | None:
        self._privateSecureNet:PrivateSecureNet = PrivateSecureNet.getShareObj(self._extendedNet)
        self._privateSecureNet.init(
            self._ed25519PivKey,
            sharedEd25519PrivateKey,
            sharedSecret
        )
        if r := self._hello(bootstrapNodeIdentify):
            logger.warning("failed to join network. (cannot hello bootstrap node)")
            return r
        with self._nodesLock:
            self._getNodesSyncronized(bootstrapNodeIdentify)
        
        logger.info("joined network.")
        return None
    
    def _getNodesSyncronized(self, nodeIdentify:NodeIdentify) -> None:
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
            return
        WaitingResponses.delete(waitingResponse)
        size = r
        gen = self._reliableNet.recvFor(
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
            return
        for nI in diff:
            if self._hello(nI) == StatusForJoinNetwork.SUCCESS:
                self._nodes[(nI.ip, nI.port)] = nI
        logger.debug(f"collected {len(nodes)} nodes.")
        return nodes
    
    def _activateRelayRoute(self) -> Generator[bytes, None, None]:
        with self._nodesLock:
            sortedNodes = self._getSortedRelayRoutesFunc(
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
            routeId = os.urandom(ANY_SESSION_ID_SIZE)
            signData = (
                routeId
                +nodeEd25519PubKeysB
            )
            self._broadcastSecureSyncronized(
                AppFlag.DIRECT
                +AppModeFlag.ACTIVATE_RELAY_ROUTE
                +ed25519.sign(signData, self._ed25519PivKey)
                +signData
            )
    
    def _recvHello(self, addr:tuple[str, int]) -> None:
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
                +itob(StatusForJoinNetwork.SUCCESS, DirectAppElementSize.STATUS_FOR_HELLO),
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
            status = StatusForJoinNetwork(btoi(statusB, ENDIAN))
        except ValueError:
            WaitingResponses.updateValue(key, StatusForJoinNetwork.UNKNOWN)
            return
        if status != StatusForJoinNetwork.SUCCESS:
            WaitingResponses.updateValue(key, status)
            return
        WaitingResponses.updateValue(key, StatusForJoinNetwork.SUCCESS)
    
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
        self._reliableNet.send(waitingResponse.nodeIdentify, sid, gen, size)
    
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
        routeId, mD = bytesSplitter.split(
            mD,
            ANY_SESSION_ID_SIZE,
            includeRest=True
        )
        nodeEd25519PubKeysBs = []
        while len(mD) >= GlobalAppElementSize.ED25519_PUBLIC_KEY:
            ed25519PubKeyB, mD = bytesSplitter.split(
                mD,
                GlobalAppElementSize.ED25519_PUBLIC_KEY,
                includeRest=True
            )
            nodeEd25519PubKeysBs.append(ed25519PubKeyB)
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
        with self._relayRoutesLock:
            self._relayRoutes[(AddrToEd25519PubKeys.get(addr).public_bytes_raw(), routeId)] = RelayRoute(
                recvNode=recvNode,
                sendNode=sendNode
            )
    
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
            Thread(target=target, args=args, daemon=True).start()
    
    def _sync(self) -> None:
        logger.info("synchronization started.")
        while True:
            with self._nodesLock:
                nodes = list(self._nodes.values())
            for nI in nodes:
                self._getNodesSyncronized(nI)
            sleep(SyncIntervalSec.DIRECT)
    
    def _pingAndRemoveNode(self, nI:NodeIdentify) -> None:
        if self._privateSecureNet.ping(nI) == None:
            with self._nodesLock:
                if (nI.ip, nI.port) in self._nodes.keys():
                    del self._nodes[(nI.ip, nI.port)]
                    logger.info(f"removed node {(nI.ip, nI.port)} (ping timeout).")
    
    def _pinger(self) -> None:
        logger.info("pinger started.")
        while True:
            with self._nodesLock:
                nodes = list(self._nodes.values())
            for nI in nodes:
                Thread(target=self._pingAndRemoveNode, args=(nI,), daemon=True).start()
            sleep(PingIntervalSec.DIRECT)
    
    def start(self) -> None:
        Thread(target=self._recv, daemon=True).start()
        Thread(target=self._sync, daemon=True).start()
        Thread(target=self._pinger, daemon=True).start()
        logger.info("DirectApp started.")