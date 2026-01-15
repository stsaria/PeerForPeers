import logging
import random
import statistics
from threading import Lock, Thread
from time import time
from typing import Callable, Generator

from app.manager.Messages import Messages, MyReplyMessages, MyReplyMessageSqlType, MyMessageSqlType, OthersMessageSqlType
from src.app.model.Message import MyMessage, OthersMessage, MyReplyMessage
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
    
        logger.info("initialized.")

    def _getFuncByCodeAndName(self, code:str, name:str) -> Callable:
        ns = {}
        exec(code, ns)
        logger.debug(f"function {name} compiled from code.")
        return ns[name]

    def setGetIAmFunc(self, code:str) -> bool:
        try:
            self._getIAmFunc = self._getFuncByCodeAndName(code, GET_I_AM_FUNC_NAME)
            logger.debug("getIAm function set successfully.")
            return True
        except Exception:
            logger.error(f"Couldn't set getIAm function. code=\n{code}", exc_info=True)
            return False

    def setGetSortedNodesFunc(self, code:str) -> bool:
        try:
            self._getSortedNodesFunc = self._getFuncByCodeAndName(code, GET_SORTED_NODES_FUNC_NAME)
            logger.debug("getSortedNodes function set successfully.")
            return True
        except Exception:
            logger.error(f"Couldn't set getSortedNodes function. code=\n{code}", exc_info=True)
            return False

    def hello(self, nodeIdentify:NodeIdentify) -> bool:
        logger.debug(f"{nodeIdentify.port}")
        if not self._secureNet.pingAndSetRedundancy(nodeIdentify, dontUpdateIfContains=False):
            logger.warning(f"{nodeIdentify.port}")
            return False
        if not self._secureNet.hello(nodeIdentify):
            logger.warning(f"{nodeIdentify.port}")
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
            logger.error(f"{nodeIdentify.port} failed (no response)")
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
        logger.debug(f"{nodeIdentify.port} succeeded")
        return True

    def _getNodesSyncronized(self, nodeIdentify:NodeIdentify, limit:int) -> list[NodeIdentify]:
        logger.debug(f"{nodeIdentify.port}")
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
            logger.warning(f"{nodeIdentify.port}")
            return []
        WaitingResponses.delete(waitingResponse)
        size = r
        if size > (
            GlobalAppElementSize.IP_STR
            +GlobalAppElementSize.PORT
            +GlobalAppElementSize.ED25519_PUBLIC_KEY
        ) * limit:
            logger.error(f"received size too large.")
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
                    logger.debug(f"node {ip}:{port} already exists.")
                    continue
                nI = NodeIdentify(
                    ip=ip,
                    port=port,
                    ed25519PublicKey=ed25519.getPubKeyByPubKeyBytes(ed25519PubKeyB)
                )
                if not self._secureNet.pingAndSetRedundancy(nI):
                    logger.debug(f"pingAndSetRedundancy failed for {ip}:{port}")
                    continue
                nodes.append(nI)
                if len(nodes) >= limit:
                    logger.debug(f"limit {limit} reached.")
                    return nodes
        logger.debug(f"collected {len(nodes)} nodes.")
        return nodes

    def _getMessages(self, nodeIdentify:NodeIdentify, limit:int) -> list[MyMessage | MyReplyMessage] | None:
        logger.debug(f"{nodeIdentify.port}")
        sid = ReliableSessionIds.issueTicket()
        waitingResponse = WaitingResponse(
            nodeIdentify,
            self,
            AppModeFlag.RESP_GET_MESSAGES,
            otherInfoInKey=sid
        )
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
            logger.warning(f"no response from {nodeIdentify.ip}:{nodeIdentify.port}")
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
                    logger.warning(f"invalid messageType received.")
                    continue
                if (timestamp := btoi(timestampB, ENDIAN)) > time():
                    logger.warning(f"received message from the future.")
                    continue
                elif timestamp < time() - MESSAGE_LIFE_SEC:
                    logger.debug(f"received expired message.")
                    continue
                elif (messageSize := btoi(messageSizeB, ENDIAN)) > MESSAGE_CONTENT_LIMIT:
                    logger.warning(f"message size too large.")
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
                        messageId
                        +timestampB
                        +messageSizeB
                        +messageContentB
                        +rootMessageId,
                        signed,
                        nodeIdentify.ed25519PublicKey
                    ):
                        logger.warning(f"signature verification failed for reply message.")
                        continue
                    message = MyReplyMessage(
                        messageId=messageId,
                        rootMessageId=rootMessageId,
                        content=messageContent,
                        timestamp=timestamp,
                        nodeIdentify=nodeIdentify
                    )
                if messageType == MessageType.MESSAGE:
                    if not ed25519.verify(
                        messageId
                        +timestampB
                        +messageSizeB
                        +messageContentB,
                        signed,
                        nodeIdentify.ed25519PublicKey
                    ):
                        logger.warning(f"signature verification failed for message.")
                        continue
                    message = MyMessage(
                        messageId=messageId,
                        content=messageContent,
                        timestamp=timestamp,
                        nodeIdentify=nodeIdentify
                    )
                messages.append(message)
                if len(messages) >= limit:
                    logger.debug(f"limit {limit} reached.")
                    return messages
        logger.debug(f"collected {len(messages)} messages.")
        return messages

    def _getOtherMessage(self, nodeIdentify:NodeIdentify, messageId:bytes) -> OthersMessage | None:
        logger.debug(f"{nodeIdentify.port}")
        waitingResponse = WaitingResponse(
            nodeIdentify,
            self,
            AppModeFlag.RESP_GET_MESSAGES,
            otherInfoInKey=messageId
        )
        WaitingResponses.addKey(waitingResponse)
        self._secureNet.sendToSecure(
            AppFlag.GLOBAL
            +AppModeFlag.GET_OTHERS_MESSAGE
            +messageId,
            nodeIdentify
        )
        if r := WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC) == None:
            WaitingResponses.delete(waitingResponse)
            logger.warning(f"no response from {nodeIdentify.ip}:{nodeIdentify.port}")
            return
        WaitingResponses.delete(waitingResponse)
        timestampB, messegeContentB, ed25519PubKey, signed = r
        timestamp = btoi(timestampB, ENDIAN)
        if timestamp > time():
            logger.warning(f"received message from the future.")
            return
        logger.debug(f"message received successfully.")
        return OthersMessage(
            messageId=messageId,
            content=btos(messegeContentB, STR_ENCODING),
            timestamp=timestamp,
            ed25519PubKey=ed25519.getPubKeyByPubKeyBytes(ed25519PubKey),
            ed25519Sign=signed
        )

    def _recvHello(self, mD:bytes, addr:tuple[str, int]) -> None:
        logger.debug(f"_recvHello from {addr}")
        with self._ipAndPortToNodesLock:
            if not self._ipAndPortToNodes.get(addr):
                logger.warning(f"node {addr} not found in ipAndPortToNodes.")
                return
        iAmInfo = mD
        if (ed25519PubKey := IpToEd25519PubKeys.get(addr[0])) == None:
            logger.warning(f"ed25519PubKey not found for {addr[0]}")
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
        logger.debug(f"node {addr} updated.")

    def _recvGetNodes(self, mD:bytes, addr:tuple[str, int]) -> None:
        logger.debug(f"_recvGetNodes from {addr}")
        sid, limitB = bytesSplitter.split(
            mD,
            ReliablePacketElementSize.SESSION_ID,
            GlobalAppElementSize.NODES_LIMIT_FOR_GET
        )
        limit = btoi(limitB, ENDIAN)
        if limit > NODES_LIMIT_FOR_GET:
            logger.warning(f"limit {limit} exceeds NODES_LIMIT_FOR_GET.")
            return
        if not (ed25519PubKey := IpToEd25519PubKeys.get(addr[0])):
            logger.warning(f"ed25519PubKey not found for {addr[0]}")
            return
        nI = NodeIdentify(
            ip=addr[0],
            port=addr[1],
            ed25519PublicKey=ed25519PubKey
        )
        waitingResponse = WaitingResponse(
            nI,
            self,
            AppModeFlag.START_SEND_REQ,
            otherInfoInKey=sid
        )
        WaitingResponses.addKey(waitingResponse)

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
        
        self._secureNet.sendToSecure(
            AppFlag.GLOBAL
            +AppModeFlag.RESP_GET_NODES
            +sid
            +len(d),
            nI
        )
        if WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC) == None:
            WaitingResponses.delete(waitingResponse)
            logger.warning(f"no start send response from {addr}")
            return
        WaitingResponses.delete(waitingResponse)
        gen:Generator = genGen()
        gen.send(d)
        self._reliableNet.send(
            nI,
            sid,
            gen,
            len(d)
        )
        logger.debug(f"sent {len(d)} bytes to {addr}")

    def _recvRespGetNodes(self, mD:bytes, addr:tuple[str, int]) -> None:
        logger.debug(f"from {addr}")
        sid = bytesSplitter.split(
            mD,
            ReliablePacketElementSize.SESSION_ID
        )[0]
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, AppModeFlag.RESP_GET_NODES, sid)
        if not WaitingResponses.containsKey(key):
            logger.warning(f"WaitingResponses does not contain key for {addr}")
            return
        WaitingResponses.updateValue(key, mD)

    def _recvGetMessages(self, mD:bytes, addr:tuple[str, int]) -> None:
        logger.debug(f"_recvGetMessages from {addr}")
        sid, limitB = bytesSplitter.split(
            mD,
            ReliablePacketElementSize.SESSION_ID,
            GlobalAppElementSize.MESSAGES_LIMIT_FOR_GET
        )
        limit = btoi(limitB, ENDIAN)
        if limit > MESSAGES_LIMIT_FOR_GET:
            logger.warning(f"limit {limit} exceeds MESSAGES_LIMIT_FOR_GET.")
            return
        if not (ed25519PubKey := IpToEd25519PubKeys.get(addr[0])):
            logger.warning(f"ed25519PubKey not found for {addr[0]}")
            return
        nI = NodeIdentify(
            ip=addr[0],
            port=addr[1],
            ed25519PublicKey=ed25519PubKey
        )
        waitingResponse = WaitingResponse(
            nI,
            self,
            AppModeFlag.START_SEND_REQ,
            otherInfoInKey=sid
        )
        WaitingResponses.addKey(waitingResponse)

        messagesToSend:tuple[MyMessageSqlType | MyReplyMessageSqlType] = (
            (MyReplyMessages if random.random() <= CHANCE_FOR_SEND_REPLY_MESSAGE else Messages).getRandom(
                limit=limit,
                raw=True
            )
        )
        d = b""
        for message in messagesToSend:
            messageTypeB = itob((MessageType.REPLY_MESSAGE if isinstance(message, MyReplyMessage) else MessageType.MESSAGE).value, GlobalAppElementSize.MESSAGE_TYPE, ENDIAN)
            messageId = message.messageId
            timestampB = itob(message.timestamp, GlobalAppElementSize.TIMESTAMP, ENDIAN)
            messageContentB = stob(message.content, STR_ENCODING)
            messageSizeB = itob(len(messageContentB), GlobalAppElementSize.MESSAGE_SIZE, ENDIAN)
            if isinstance(message, MyReplyMessage):
                rootMessageId = message.rootMessageId
                d += (
                    messageTypeB
                    +messageId
                    +timestampB
                    +messageSizeB
                    +messageContentB
                    +rootMessageId
                )
            else:
                d += (
                    messageTypeB
                    +messageId
                    +timestampB
                    +messageSizeB
                    +messageContentB
                )
        self._secureNet.sendToSecure(
            AppFlag.GLOBAL
            +AppModeFlag.RESP_GET_MESSAGES
            +sid
            +len(d),
            nI
        )
        if WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC) == None:
            WaitingResponses.delete(waitingResponse)
            logger.warning(f"no start send response from {addr}")
            return
        WaitingResponses.delete(waitingResponse)
        gen:Generator = genGen()
        gen.send(d)
        self._reliableNet.send(
            nI,
            sid,
            gen,
            len(d)
        )
        logger.debug(f"sent {len(d)} bytes to {addr}")

    def _recvRespGetMessages(self, mD:bytes, addr:tuple[str, int]) -> None:
        logger.debug(f"from {addr}")
        sid = bytesSplitter.split(
            mD,
            ReliablePacketElementSize.SESSION_ID
        )[0]
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, AppModeFlag.RESP_GET_MESSAGES, sid)
        if not WaitingResponses.containsKey(key):
            logger.warning(f"WaitingResponses does not contain key for {addr}")
            return
        WaitingResponses.updateValue(key, mD)

    def _recvGetOthersMessage(self, mD:bytes, addr:tuple[str, int]) -> None:
        logger.debug(f"_recvGetOthersMessage from {addr}")
        messageId = bytesSplitter.split(
            mD,
            GlobalAppElementSize.MESSAGE_ID
        )[0]
        if not (ed25519PubKey := IpToEd25519PubKeys.get(addr[0])):
            logger.warning(f"ed25519PubKey not found for {addr[0]}")
            return
        nI = NodeIdentify(
            ip=addr[0],
            port=addr[1],
            ed25519PublicKey=ed25519PubKey
        )
        message:OthersMessageSqlType = Messages.get(messageId, raw=True)
        if not message:
            logger.warning(f"message not found for id {messageId}")
            return
        ed25519PubKey = message[0]
        messageId = message[1]
        messegeContentB = stob(message[2], STR_ENCODING)
        timestampB = itob(message[3], GlobalAppElementSize.TIMESTAMP, ENDIAN)
        signed = message[4]
        self._secureNet.sendToSecure(
            AppFlag.GLOBAL
            +AppModeFlag.RESP_GET_OTHER_MESSAGE
            +messageId
            +timestampB
            +ed25519PubKey
            +signed
            +messegeContentB,
            nI
        )
        logger.debug(f"sent message {messageId} to {addr}")

    def _recvRespGetOtherMessage(self, mD:bytes, addr:tuple[str, int]) -> None:
        logger.debug(f"from {addr}")
        messageId, mD = bytesSplitter.split(
            mD,
            GlobalAppElementSize.MESSAGE_ID,
            includeRest=True
        )[0]
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, AppModeFlag.RESP_GET_OTHER_MESSAGE, messageId)
        if not WaitingResponses.containsKey(key):
            logger.warning(f"WaitingResponses does not contain key for {addr}")
            return
        timestampB, ed25519PubKeyB, signed, messegeContentB = bytesSplitter.split(
            mD,
            GlobalAppElementSize.TIMESTAMP,
            GlobalAppElementSize.ED25519_PUBLIC_KEY,
            GlobalAppElementSize.ED25519_SIGN,
            includeRest=True
        )
        WaitingResponses.updateValue(key, (timestampB, messegeContentB, ed25519PubKeyB, signed))

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

    def _recvRespHello(self, mD:bytes, addr:tuple[str, int]) -> None:
        logger.debug(f"_recvRespHello from {addr}")
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, AppModeFlag.RESP_HELLO)
        if not WaitingResponses.containsKey(key):
            logger.warning(f"WaitingResponses does not contain key for {addr}")
            return
        WaitingResponses.updateValue(key, mD)
    


    def _recv(self) -> None:
        logger.info("thread started.")
        for data, addr in self._secureNet.recv():
            pFlag, mFlag, mainData = bytesSplitter.split(
                data,
                GlobalAppElementSize.APP_FLAG,
                GlobalAppElementSize.MODE_FLAG,
                includeRest=True
            )
            if btoi(pFlag, ENDIAN) != AppFlag.GLOBAL.value:
                logger.debug(f"ignored packet from {addr} (not GLOBAL flag)")
                continue
            try:
                mFlag = AppModeFlag(btoi(mFlag, ENDIAN))
            except ValueError:
                logger.warning(f"invalid mode flag from {addr}")
                continue
            if mFlag == AppModeFlag.HELLO:
                target, args = self._recvHello, (mainData, addr)
            elif mFlag == AppModeFlag.RESP_HELLO:
                target, args = self._recvRespHello, (mainData, addr)
            
            with self._ipAndPortToNodesLock:
                contains = addr in self._ipAndPortToNodes
            if contains:
                match mFlag:
                    case AppModeFlag.GET_NODES:
                        target, args = self._recvGetNodes, (mainData, addr)
                    case AppModeFlag.RESP_GET_NODES:
                        target, args = self._recvRespGetNodes, (mainData, addr)
                    case AppModeFlag.GET_MESSAGES:
                        target, args = self._recvGetMessages, (mainData, addr)
                    case AppModeFlag.RESP_GET_MESSAGES:
                        target, args = self._recvRespGetMessages, (mainData, addr)
                    case AppModeFlag.GET_OTHERS_MESSAGE:
                        target, args = self._recvGetOthersMessage, (mainData, addr)
                    case AppModeFlag.RESP_GET_OTHER_MESSAGE:
                        target, args = self._recvRespGetOtherMessage, (mainData, addr)
                    case AppModeFlag.START_SEND_REQ:
                        target, args = self._recvStartSendReq, (mainData, addr)
            Thread(target=target, args=args, daemon=True).start()

    def _sync(self) -> None:
        logger.info("_sync thread started.")
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
            logger.debug(f"collected {len(messages)} messages in this sync loop.")


    def start(self) -> None:
        Thread(target=self._recv, daemon=True).start()
        Thread(target=self._sync, daemon=True).start()

