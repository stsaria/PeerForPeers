import logging
import random
import statistics
from threading import Lock, Thread
from time import time
from typing import Callable, Generator

from src.app.model.Message import Message, OthersMessage, OthersReplyMessage, ReplyMessage
from manager.IpAndPortToEd25519PubKeys import IpToEd25519PubKeys
from manager.ReliableSessionIds import ReliableSessionIds
from manager.WaitingResponses import WaitingResponses
from model.WaitingResponse import WAITING_RESPONSE_KEY, WaitingResponse
from src.protocol.ProgramProtocol import TIME_OUT_MILLI_SEC, PING_WINDOW
from src.protocol.Protocol import *
from src.app.model.Node import Node
from app.protocol.Protocol import *
from app.protocol.ProgramProtocol import *
from src.protocol.Protocol import *
from src.model.NodeIdentify import NodeIdentify
from src.core.ExtendedNet import ExtendedNet
from src.core.ReliableNetController import ReliableNet
from src.core.SecureNet import SecureNet
from src.model.NetConfig import SecureNetConfig
from util import bytesSplitter, ed25519, encrypter
from util.ed25519 import Ed25519PrivateKey
from util.bytesCoverter import btoi, btos, itob, stob

logger = logging.getLogger()

def genGen() -> Generator:
    if False:
        yield

class GlobalApp:
    def __init__(self, netConfig:SecureNetConfig):
        self._ed25519PivKey:Ed25519PrivateKey = netConfig.ed25519PrivateKey
        self._extendedNet:ExtendedNet = ExtendedNet(netConfig)
        self._secureNet:SecureNet = SecureNet.getShareObj(self._extendedNet)
        self._secureNet.init(netConfig.ed25519PrivateKey)
        self._reliableNet:ReliableNet = ReliableNet(self._extendedNet, netConfig.ed25519PrivateKey)

        self._ipAndPortToNodes:dict[tuple[str, int], Node] = {}
        self._ipAndPortToNodesLock:Lock = Lock()

        self._getIAmFunc:Callable[[], bytes] = lambda: b""
        self._getSortedNodesFunc:Callable[[list[Node]], list[Node]] = lambda node: node
    
    def _getFuncByCodeAndName(self, code:str, name:str) -> Callable:
        ns = {}
        exec(code, ns)
        return ns[name]
    def setGetIAmFunc(self, code:str) -> bool:
        try:
            self._getIAmFunc = self._getFuncByCodeAndName(code, GET_I_AM_FUNC_NAME)
            return True
        except IndexError:
            logger.error(f"Couldn't set getIAm function. code=\n{code}", exc_info=True)
            return False
    def setGetSortedNodesFunc(self, code:str) -> bool:
        try:
            self._getIAmFunc = self._getFuncByCodeAndName(code, GET_SORTED_NODES_FUNC_NAME)
            return True
        except IndexError:
            logger.error(f"Couldn't set getSortedNodes function. code=\n{code}", exc_info=True)
            return False
    def hello(self, nodeIdentify:NodeIdentify) -> bool:
        logger.debug(f"GlobalApp: hello to {nodeIdentify.ip}:{nodeIdentify.port}")
        if not self._secureNet.pingAndSetRedundancy(nodeIdentify, dontUpdateIfContains=False):
            return False
        if not self._secureNet.hello(nodeIdentify):
            return False
        waitingResponse = WaitingResponse(
            nodeIdentify,
            self,
            AppModeFlag.RESP_HELLO
        )
        WaitingResponses.addKey(waitingResponse)
        self._secureNet.sendToSecure(
            AppFlag.GLOBAL
            +AppModeFlag.HELLO
            +self._getIAmFunc(),
            nodeIdentify
        )
        if r := WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC) == None:
            WaitingResponses.delete(waitingResponse)
            return False
        WaitingResponses.delete(waitingResponse)
        with self._ipAndPortToNodesLock:
            self._ipAndPortToNodes[(nodeIdentify.ip, nodeIdentify.port)] = Node(
                ip=nodeIdentify.ip,
                port=nodeIdentify.port,
                ed25519PublicKey=nodeIdentify.ed25519PublicKey,
                pingDelay=statistics.median([self._secureNet.ping(nodeIdentify) for _ in range(PING_WINDOW)]),
                iAmInfo=r,
                startTimestamp=time()
            )
        return True
    def _getNodesSyncronized(self, nodeIdentify:NodeIdentify, limit:int) -> list[NodeIdentify]:
        waitingResponse = WaitingResponse(
            nodeIdentify,
            self,
            AppModeFlag.RESP_GET_NODES
        )
        WaitingResponses.addKey(waitingResponse)
        sid = ReliableSessionIds.issueTicket()
        self._secureNet.sendToSecure(
            AppFlag.GLOBAL
            +AppModeFlag.GET_NODES
            +sid
            +itob(limit, GlobalAppElementSize.NODES_LIMIT_FOR_GET),
            nodeIdentify
        )
        if r := WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC) == None:
            WaitingResponses.delete(waitingResponse)
            return []
        WaitingResponses.delete(waitingResponse)
        size = r
        if size > (
            GlobalAppElementSize.IP_STR
            +GlobalAppElementSize.PORT
            +GlobalAppElementSize.ED25519_PUBLIC_KEY
        ) * limit:
            return []

        gen = self._reliableNet.recvFor(
            sid,
            size,
            nodeIdentify.ed25519PublicKey
        )
        self._secureNet.sendToSecure(
            AppFlag.GLOBAL
            +AppModeFlag.START_SEND_REQ
            +sid,
            nodeIdentify
        )
        cache = b""
        nodes = []
        for data in gen:
            cache += data
            while len(cache) >= (
                GlobalAppElementSize.IP_STR
                +GlobalAppElementSize.PORT
                +GlobalAppElementSize.ED25519_PUBLIC_KEY
            ):
                ipStrB, portB, ed25519PubKeyB, cache = bytesSplitter.split(
                    cache,
                    GlobalAppElementSize.IP_STR,
                    GlobalAppElementSize.PORT,
                    GlobalAppElementSize.ED25519_PUBLIC_KEY,
                    includeRest=True
                )
                ip = btos(ipStrB, STR_ENCODING)
                port = btoi(portB, ENDIAN)
                if (ip, port) in self._ipAndPortToNodes.keys():
                    continue
                nI = NodeIdentify(
                    ip=ip,
                    port=port,
                    ed25519PublicKey=ed25519.getPubKeyByPubKeyBytes(ed25519PubKeyB)
                )
                if not self._secureNet.pingAndSetRedundancy(nI):
                    continue
                nodes.append(nI)
                if len(nodes) >= limit:
                    return nodes
        return nodes
    def _getMessages(self, nodeIdentify:NodeIdentify, limit:int) -> list[Message | ReplyMessage] | None:
        waitingResponse = WaitingResponse(
            nodeIdentify,
            self,
            AppModeFlag.RESP_GET_MESSAGES
        )
        sid = ReliableSessionIds.issueTicket()
        WaitingResponses.addKey(waitingResponse)
        self._secureNet.sendToSecure(
            AppFlag.GLOBAL
            +AppModeFlag.GET_MESSAGES
            +sid
            +itob(limit, GlobalAppElementSize.MESSAGES_LIMIT_FOR_GET),
            nodeIdentify
        )
        if r := WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC) == None:
            WaitingResponses.delete(waitingResponse)
            return
        WaitingResponses.delete(waitingResponse)
        gen = self._reliableNet.recvFor(
            sid,
            r,
            nodeIdentify.ed25519PublicKey
        )
        self._secureNet.sendToSecure(
            AppFlag.GLOBAL
            +AppModeFlag.START_SEND_REQ
            +sid,
            nodeIdentify
        )
        cache = b""
        messages = []
        for data in gen:
            cache += data
            while len(cache) >= (
                GlobalAppElementSize.MESSAGE_TYPE
                +GlobalAppElementSize.MESSAGE_ID
                +GlobalAppElementSize.TIMESTAMP
                +GlobalAppElementSize.ED25519_SIGN
                +GlobalAppElementSize.MESSAGE_SIZE
            ):
                messageTypeB, messageId, timestampB, signed, messageSizeB, cache = bytesSplitter.split(
                    cache,
                    GlobalAppElementSize.MESSAGE_TYPE,
                    GlobalAppElementSize.MESSAGE_ID,
                    GlobalAppElementSize.TIMESTAMP,
                    GlobalAppElementSize.ED25519_SIGN,
                    GlobalAppElementSize.MESSAGE_SIZE,
                    includeRest=True
                )
                try:
                    messageType = MessageType(btoi(messageTypeB, ENDIAN))
                except ValueError:
                    continue
                if (timestamp := btoi(timestampB, ENDIAN)) > time():
                    continue
                elif timestamp < time() - MESSAGE_LIFE_SEC:
                    continue
                elif (messageSize := btoi(messageSizeB, ENDIAN)) > MESSAGE_CONTENT_LIMIT:
                    continue
                messageContentB, cache = bytesSplitter.split(
                    cache,
                    messageSize,
                    includeRest=True
                )
                messageContent = btos(messageContentB, STR_ENCODING)
                if messageType == MessageType.REPLY_MESSAGE:
                    rootMessageId, cache = bytesSplitter.split(
                        cache,
                        GlobalAppElementSize.MESSAGE_ID,
                        includeRest=True
                    )
                    if not ed25519.verify(
                        messageTypeB
                        +messageId
                        +timestampB
                        +messageSizeB
                        +messageContentB
                        +rootMessageId,
                        signed,
                        nodeIdentify.ed25519PublicKey
                    ):
                        continue
                    message = OthersReplyMessage(
                        messageId=messageId,
                        rootMessageId=rootMessageId,
                        content=messageContent,
                        timestamp=timestamp,
                        nodeIdentify=nodeIdentify
                    )
                if messageType == MessageType.MESSAGE:
                    if not ed25519.verify(
                        messageTypeB
                        +messageId
                        +timestampB
                        +messageSizeB
                        +messageContentB,
                        signed,
                        nodeIdentify.ed25519PublicKey
                    ):
                        continue
                    message = OthersMessage(
                        messageId=messageId,
                        content=messageContent,
                        timestamp=timestamp,
                        nodeIdentify=nodeIdentify
                    )
                messages.append(message)
                if len(messages) >= limit:
                    return messages
        return messages 
    


    def _recvHello(self, mD:bytes, addr:tuple[str, int]) -> None:
        with self._ipAndPortToNodesLock:
            if not self._ipAndPortToNodes.get(addr):
                return
        iAmInfo = mD
        if (ed25519PubKey := IpToEd25519PubKeys.get(addr[0])) == None:
            return
        self._secureNet.sendToSecure(
            AppFlag.GLOBAL
            +AppModeFlag.HELLO
            +self._getIAmFunc(),
            (nI := NodeIdentify(
                ip=addr[0],
                port=addr[1],
                ed25519PublicKey=ed25519PubKey
            ))
        )
        with self._ipAndPortToNodesLock:
            self._ipAndPortToNodes[addr] = Node(
                ip=addr[0],
                port=addr[1],
                ed25519PublicKey=ed25519PubKey,
                pingDelay=statistics.median([self._secureNet.ping(nI) for _ in range(PING_WINDOW)]),
                iAmInfo=iAmInfo,
                startTimestamp=time()
            )
    def _recvGetNodes(self, mD:bytes, addr:tuple[str, int]) -> None:
        sid, limitB = bytesSplitter.split(
            mD,
            ReliablePacketElementSize.SESSION_ID,
            GlobalAppElementSize.NODES_LIMIT_FOR_GET
        )
        limit = btoi(limitB, ENDIAN)
        with self._ipAndPortToNodesLock:
            sendAddrs = random.sample(
                list(self._ipAndPortToNodes.keys()),
                min(limit, len(self._ipAndPortToNodes))
            )
        d = b""
        for sendAddr in sendAddrs:
            if sendAddr == addr:
                continue
            d += (
                stob(sendAddr[0], GlobalAppElementSize.IP_STR, STR_ENCODING)
                +itob(sendAddr[1], GlobalAppElementSize.PORT, ENDIAN)
                +self._ipAndPortToNodes[sendAddr].ed25519PublicKey.public_bytes_raw()
                +self._ipAndPortToNodes[sendAddr].iAmInfo
            )
        gen:Generator = genGen()
        gen.send(d)
        self._reliableNet.send(
            NodeIdentify(
                ip=addr[0],
                port=addr[1],
                ed25519PublicKey=IpToEd25519PubKeys
            ),
            sid,
            gen,
            len(d)
        )
    def _recvRespHello(self, mD:bytes, addr:tuple[str, int]) -> None:
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, AppModeFlag.RESP_HELLO)
        if not WaitingResponses.containsKey(key):
            return
        WaitingResponses.updateValue(key, mD)
    


    def _recv(self) -> None:
        for data, addr in self._secureNet.recv():
            pFlag, mFlag, mainData = bytesSplitter.split(
                data,
                GlobalAppElementSize.APP_FLAG,
                GlobalAppElementSize.MODE_FLAG,
                includeRest=True
            )
            if btoi(pFlag, ENDIAN) != AppFlag.GLOBAL.value:
                continue
            try:
                mFlag = AppModeFlag(btoi(mFlag, ENDIAN))
            except ValueError:
                continue
            if mFlag == AppModeFlag.HELLO:
                target, args = self._recvHello, (mainData, addr)
            elif mFlag == AppModeFlag.RESP_HELLO:
                target, args = self._recvRespHello, (mainData, addr)
            
            with self._ipAndPortToNodesLock:
                contains = addr in self._ipAndPortToNodes
            if contains:
                pass
            Thread(target=target, args=args, daemon=True).start()

    def _sync(self) -> None:
        while True:
            with self._ipAndPortToNodesLock:
                sortedNodes = self._getSortedNodesFunc(list(self._ipAndPortToNodes.values()))
                e = False
                if len(sortedNodes) > MAX_NODES-MAX_NODES_MARGIN:
                    for n in sortedNodes[MAX_NODES-MAX_NODES_MARGIN:]:
                        sortedNodes.remove(n)
                    e = True
                self._ipAndPortToNodes.clear()
                for n in sortedNodes:
                    self._ipAndPortToNodes[(n.ip, n.port)] = n
                    if len(self._ipAndPortToNodes) < MAX_NODES-MAX_NODES_MARGIN:
                        for nI in self._getNodesSyncronized(
                            n,
                            min(NODES_LIMIT_FOR_GET, MAX_NODES-len(self._ipAndPortToNodes))
                        ):
                            if not self._ipAndPortToNodes.get((nI.ip, nI.port)):
                                self.hello(nI)
                sortedNodes = self._getSortedNodesFunc(list(self._ipAndPortToNodes.values()))
            messages = []
            for n in sortedNodes:
                if len(messages) >= MESSAGES_LIMIT_FOR_GET:
                    break
                if m := self._getMessages(n, min(MESSAGES_LIMIT_FOR_GET - len(messages), MESSAGES_LIMIT_FOR_GET)):
                    messages.extend(m)
                



                

    def start(self) -> None:
        Thread(target=self._recv, daemon=True).start()
        Thread(target=self._sync, daemon=True).start()

    