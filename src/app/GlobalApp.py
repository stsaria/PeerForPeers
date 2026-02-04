import copy
import json
import logging
import os
import random
import shutil
import statistics
from threading import Condition, Event, Lock, Thread
from time import sleep, time
from typing import Generator

from src.app.manager.Messages import AllMessageType, MessagePutStatus, Messages, MyMessages, MyReplyMessages, MyReplyMessageSqlType, MyMessageSqlType, OthersMessageSqlType, OthersMessages
from src.core.Gossiper import Gossiper
from src.manager.CustomFuncs import CustomFunc, CustomFuncs
from src.app.model.Message import MessageForSorting, MyMessage, OthersMessage, MyReplyMessage, OthersReplyMessage
from src.manager.AddrToEd25519PubKeys import AddrToEd25519PubKeys
from src.manager.ReliableSessionIds import ReliableSessionIds
from src.manager.WaitingResponses import WaitingResponses
from src.model.WaitingResponse import WAITING_RESPONSE_KEY, WaitingResponse
from src.protocol.ProgramProtocol import SAVED_PATH, TIME_OUT_MILLI_SEC, PING_WINDOW
from src.protocol.Protocol import *
from src.app.model.Node import Node
from src.app.protocol.Protocol import *
from src.app.protocol.ProgramProtocol import *
from src.protocol.Protocol import *
from src.model.NodeIdentify import NodeIdentify
from src.core.ExtendedNet import ExtendedNet
from src.core.ReliableNetController import ReliableNetController
from src.core.SecureNet import SecureNet
from src.model.NetConfig import SecureNetConfig
from src.util import bytesSplitter, ed25519
from src.util.ed25519 import Ed25519PrivateKey
from src.util.bytesCoverter import btoi, btos, itob, stob
from src.util.gene import getGen

logger = logging.getLogger(__name__)

class GlobalApp:
    def __init__(self, netConfig:SecureNetConfig, ):
        self._ed25519PivKey:Ed25519PrivateKey = netConfig.ed25519PrivateKey
        self._extendedNet:ExtendedNet = ExtendedNet(netConfig)
        self._secureNet:SecureNet = SecureNet.getShareObj(self._extendedNet)
        self._secureNet.init(netConfig.ed25519PrivateKey)
        self._reliableNet:ReliableNetController = ReliableNetController(self._extendedNet, netConfig.ed25519PrivateKey)
        self._gossiper:Gossiper = Gossiper(self._extendedNet, netConfig.ed25519PrivateKey)

        self._friends:set[NodeIdentify] = set()
        self._waitingFriends:set[NodeIdentify] = set()
        self._reqFirends:set[NodeIdentify] = set()

        self._friendsLock:Lock = Lock()

        self._waitingOfflineFriendPubKeys:set[bytes] = set()
        self._waitingOfflineFriendPubKeysLock:Lock = Lock()

        self._ignoreReqFirends:bool = False
        self._ignoreReqFirendsLock:Lock = Lock()

        self._ipAndPortToNodes:dict[tuple[str, int], Node] = {}
        self._ipAndPortToNodesCond:Condition = Condition(Lock())

        self._messages:dict[bytes, MessageForSorting] = {}
        self._messagesLock:Lock = Lock()
    
        logger.info("initialized.")
    
    def setIgnoreReqFriends(self, ignore:bool) -> None:
        with self._ignoreReqFirendsLock:
            self._ignoreReqFirends = ignore

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
            +CustomFuncs.get(CustomFunc.GET_I_AM)(),
            nodeIdentify
        )
        if r := WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC) == None:
            WaitingResponses.delete(waitingResponse)
            logger.error(f"{nodeIdentify.port} failed (no response)")
            return False
        WaitingResponses.delete(waitingResponse)
        with self._ipAndPortToNodesCond:
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
    
    def _waitRespFriend(self, waitingResponse:WaitingResponse, stop:Event) -> None:
        with self._friendsLock:
            self._waitingFriends.add(waitingResponse.nodeIdentify)
        if WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC, stop) == None:
            WaitingResponses.delete(waitingResponse)
            logger.warning(f"failed to add friend {waitingResponse.nodeIdentify.port}")
            with self._friendsLock:
                self._waitingFriends.remove(waitingResponse.nodeIdentify)
            return
        WaitingResponses.delete(waitingResponse)
        logger.debug(f"successfully added friend {waitingResponse.nodeIdentify.port}")
        self._secureNet.sendToSecure(
            AppFlag.GLOBAL
            +AppModeFlag.SECOND_RESP_FRIEND,
            waitingResponse.nodeIdentify
        )
        with self._friendsLock:
            self._waitingFriends.remove(waitingResponse.nodeIdentify)
            self._friends.add(waitingResponse.nodeIdentify)
            with open(SAVED_PATH+FRIENDS_PUBKEYS_FILE, "w") as f:
                f.write(json.dumps(list(self._friends)))
        
    def addFriend(self, nodeIdentify:NodeIdentify) -> bool:
        with self._friendsLock:
            if len(self._friends)+len(self._waitingFriends) >= MAX_FIRENDS:
                logger.warning(f"too many friend adding processes ongoing.")
                return False
        waitingResponse = WaitingResponse(
            nodeIdentify,
            self,
            AppModeFlag.RESP_FRIEND
        )
        WaitingResponses.addKey(waitingResponse)
        self._secureNet.sendToSecure(
            AppFlag.GLOBAL
            +AppModeFlag.REQ_FRIEND,
            nodeIdentify
        )
        Thread(target=self._waitRespFriend, args=(waitingResponse, None), daemon=True).start()
        return True
    
    def getFirends(self) -> list[NodeIdentify]:
        with self._friendsLock:
            return list(self._friends)
    
    def getOnlineFriends(self) -> list[NodeIdentify]:
        friends = self.getFirends()
        onlineFriends:list[NodeIdentify] = []
        with self._ipAndPortToNodesCond:
            nodes = self._ipAndPortToNodes.values()
        for n in nodes:
            if (n := NodeIdentify(
                ip=n.ip,
                port=n.port,
                ed25519PublicKey=n.ed25519PublicKey
            )) in friends:
                onlineFriends.append(n)
        return onlineFriends
    
    def getWaitingFriends(self) -> list[NodeIdentify]:
        with self._friendsLock:
            return list(self._waitingFriends)
    
    def getReqFriends(self) -> list[NodeIdentify]:
        with self._friendsLock:
            return list(self._reqFirends)
    
    def acceptReqFriend(self, nodeIdentify:NodeIdentify) -> bool:
        with self._friendsLock:
            if nodeIdentify not in self._reqFirends:
                logger.warning(f"no friend request from {nodeIdentify.port}")
                return False
            self._reqFirends.remove(nodeIdentify)
        WaitingResponse = WaitingResponse(
            nodeIdentify,
            self,
            AppModeFlag.SECOND_RESP_FRIEND
        )
        WaitingResponses.addKey(WaitingResponse)
        self._secureNet.sendToSecure(
            AppFlag.GLOBAL
            +AppModeFlag.RESP_FRIEND,
            nodeIdentify
        )
        if WaitingResponses.waitAndGet(WaitingResponse, TIME_OUT_MILLI_SEC) == None:
            WaitingResponses.delete(WaitingResponse)
            return False
        WaitingResponses.delete(WaitingResponse)
        with self._friendsLock:
            self._friends.add(nodeIdentify)
            with open(SAVED_PATH+FRIENDS_PUBKEYS_FILE, "w") as f:
                f.write(json.dumps(list(self._friends)))
        logger.debug(f"accepted friend request from {nodeIdentify.port}")
        return True
    
    def checkAmIFirend(self, nodeIdentify:NodeIdentify) -> bool:
        with self._friendsLock:
            if not nodeIdentify in self._friends:
                return False
        waitingResponse = WaitingResponse(
            nodeIdentify,
            self,
            AppModeFlag.RESP_AM_I_FRIEND
        )
        WaitingResponses.addKey(waitingResponse)
        self._secureNet.sendToSecure(
            AppFlag.GLOBAL
            +AppModeFlag.AM_I_FRIEND,
            nodeIdentify
        )
        if WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC) == None:
            WaitingResponses.delete(waitingResponse)
            return False
        WaitingResponses.delete(waitingResponse)
        return True
    
    def removeFriend(self, nodeIdentify:NodeIdentify) -> None:
        with self._friendsLock:
            if nodeIdentify in self._friends:
                self._friends.remove(nodeIdentify)
                with open(SAVED_PATH+FRIENDS_PUBKEYS_FILE, "w") as f:
                    f.write(json.dumps(list(self._friends)))
    
    def postMessage(self, content:str) -> MessagePutStatus:
        msg = MyMessage(
            messageId=os.urandom(GlobalAppElementSize.MESSAGE_ID),
            content=content,
            timestamp=int(time())
        )
        return MyMessages.put(msg)

    def postReplyMessage(self, rootMessage:OthersMessage, content:str) -> bool:
        msg = MyReplyMessage(
            messageId=os.urandom(GlobalAppElementSize.MESSAGE_ID),
            rootMessageId=rootMessage.messageId,
            content=content,
            timestamp=int(time())
        )
        if MyReplyMessages.put(msg) != MessagePutStatus.SUCCESS:
            return False
        elif OthersMessages.put(rootMessage) != MessagePutStatus.SUCCESS:
            return False
        return True

    def getMyMessages(self) -> list[MyMessage]:
        return MyMessages.getAll()

    def getMyReplyMessages(self) -> list[MyReplyMessage]:
        return MyReplyMessages.getAll()

    def getMessages(self, onlyOthers:bool = False) -> dict[OthersMessage, list[OthersMessage]]:
        with self._messagesLock:
            messages = copy.deepcopy(self._messages)
        if onlyOthers:
            return list(messages.values())
        myMessages = MyMessages.getAll()
        for message in myMessages:
            if message.messageId in messages.keys():
                messages[message.messageId].message = message
        myReplyMessages = MyReplyMessages.getAll()
        for message in myReplyMessages:
            if message.rootMessageId in messages.keys():
                messages[message.rootMessageId].replies.append(message)
            else:
                messages[message.rootMessageId] = MessageForSorting(
                    message=None,
                    replies=[message]
                )
        return list(messages.values())

    def _waitAndAddFriendNode(self, pubKey:bytes) -> None:
        nI = self._gossiper.waitAndGetNodeByPublicKey(pubKey, None)
        if not self.hello(nI):
            logger.warning(f"failed to add friend node {nI.port}")
            return
        if not self.checkAmIFirend(nI):
            logger.warning(f"not a friend node {nI.port}")
            return
        logger.debug(f"friend node {nI.port} added.")
    
    def _syncFirends(self) -> None:
        waitNodePubKeyAndEvents:dict[bytes, Event] = {}
        with self._ipAndPortToNodesCond:
            while True:
                if self._ipAndPortToNodesCond.wait(None):
                    with self._friendsLock:
                        friends = list(self._friends)
                    for f in friends:
                        if (f.ip, f.port) in self._ipAndPortToNodes.keys() or f.ed25519PublicKey.public_bytes_raw() in waitNodePubKeyAndEvents.keys():
                            continue
                        waitNodePubKeyAndEvents[f.ed25519PublicKey.public_bytes_raw()] = Event()
                        Thread(target=self._waitAndAddFriendNode, args=(f.ed25519PublicKey.public_bytes_raw(),), daemon=True).start()
                with self._friendsLock:
                    friendPubKeys = [f.ed25519PublicKey.public_bytes_raw() for f in self._friends]
                    for k, e in waitNodePubKeyAndEvents.items():
                        if not k in friendPubKeys:
                            e.set()

    def _getNodesSyncronized(self, nodeIdentify:NodeIdentify, limit:int) -> list[NodeIdentify]:
        sid = ReliableSessionIds.issueTicket()
        waitingResponse = WaitingResponse(
            nodeIdentify,
            self,
            AppModeFlag.RESP_GET_NODES,
            otherInfoInKey=sid
        )
        WaitingResponses.addKey(waitingResponse)
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
            GlobalAppElementSize.IP
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
                    message = OthersReplyMessage(
                        ed25519PubKey=nodeIdentify.ed25519PublicKey,
                        ed25519Sign=signed,
                        messageId=messageId,
                        rootMessageId=rootMessageId,
                        content=messageContent,
                        timestamp=timestamp
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
                    message = OthersMessage(
                        ed25519PubKey=nodeIdentify.ed25519PublicKey,
                        ed25519Sign=signed,
                        messageId=messageId,
                        content=messageContent,
                        timestamp=timestamp
                    )
                messages.append(message)
                if len(messages) >= limit:
                    logger.debug(f"limit {limit} reached.")
                    return messages
        logger.debug(f"collected {len(messages)} messages.")
        return messages

    def _getOthersMessage(self, nodeIdentify:NodeIdentify, messageId:bytes) -> OthersMessage | None:
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
        iAmInfo = mD
        if (ed25519PubKey := AddrToEd25519PubKeys.get(addr[0])) == None:
            return
        with self._ipAndPortToNodesCond:
            if addr in self._ipAndPortToNodes.keys():
                return
        self._secureNet.sendToSecure(
            AppFlag.GLOBAL
            +AppModeFlag.RESP_HELLO
            +CustomFuncs.get(CustomFunc.GET_I_AM)(),
            (nI := NodeIdentify(
                ip=addr[0],
                port=addr[1],
                ed25519PublicKey=ed25519PubKey
            ))
        )
        with self._ipAndPortToNodesCond:
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
        if not (ed25519PubKey := AddrToEd25519PubKeys.get(addr[0])):
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

        with self._ipAndPortToNodesCond:
            sendAddrs = random.sample(
                list(self._ipAndPortToNodes.keys()),
                min(limit, len(self._ipAndPortToNodes))
            )
        d = b""
        for sendAddr in sendAddrs:
            if sendAddr == addr:
                continue
            d += (
                stob(sendAddr[0], GlobalAppElementSize.IP, STR_ENCODING)
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
        gen:Generator = getGen()
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
        sid, size = bytesSplitter.split(
            mD,
            ReliablePacketElementSize.SESSION_ID,
            GlobalAppElementSize.NODES_SIZE
        )[0]
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, AppModeFlag.RESP_GET_NODES, sid)
        if not WaitingResponses.containsKey(key):
            logger.warning(f"WaitingResponses does not contain key for {addr}")
            return
        WaitingResponses.updateValue(key, size)

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
        if not (ed25519PubKey := AddrToEd25519PubKeys.get(addr[0])):
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
            messageContentB = stob(message.content, 0, STR_ENCODING)
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
        gen:Generator = getGen()
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
        if not (ed25519PubKey := AddrToEd25519PubKeys.get(addr[0])):
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
        messegeContentB = stob(message[2], 0, STR_ENCODING)
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
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, AppModeFlag.RESP_HELLO)
        if not WaitingResponses.containsKey(key):
            logger.warning(f"WaitingResponses does not contain key for {addr}")
            return
        WaitingResponses.updateValue(key, mD)
    
    def _recvReqFriend(self, addr:tuple[str, int]) -> None:
        with self._ignoreReqFirendsLock:
            if self._ignoreReqFirends:
                logger.debug(f"ignoring req friend from {addr}")
                return
        nI = NodeIdentify(
            ip=addr[0],
            port=addr[1],
            ed25519PublicKey=AddrToEd25519PubKeys.get(addr)
        )
        with self._friendsLock:
            self._reqFirends.add(nI)
    
    def _recvRespFriend(self, addr:tuple[str, int]) -> None:
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, AppModeFlag.RESP_FRIEND)
        if not WaitingResponses.containsKey(key):
            return
        WaitingResponses.updateValue(key, 1)
    
    def _recvSecondRespFriend(self, addr:tuple[str, int]) -> None:
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, AppModeFlag.SECOND_RESP_FRIEND)
        if not WaitingResponses.containsKey(key):
            return
        WaitingResponses.updateValue(key, 1)
    
    def _recvAmIFirend(self, addr:tuple[str, int]) -> None:
        nI = NodeIdentify(
            ip=addr[0],
            port=addr[1],
            ed25519PublicKey=AddrToEd25519PubKeys.get(addr)
        )
        with self._friendsLock:
            if not nI in self._friends:
                return
        self._secureNet.sendToSecure(
            AppFlag.GLOBAL
            +AppModeFlag.RESP_AM_I_FRIEND,
            nI
        )
    
    def _recvRespAmIFirend(self, addr:tuple[str, int]) -> None:
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, AppModeFlag.RESP_AM_I_FRIEND)
        if not WaitingResponses.containsKey(key):
            return
        WaitingResponses.updateValue(key, 1)
        
    def _recv(self) -> None:
        logger.info("thread started.")
        for data, addr in self._secureNet.recv():
            if len(data) < GlobalAppElementSize.APP_FLAG+GlobalAppElementSize.MODE_FLAG:
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
                target, args = self._recvHello, (mainData, addr)
            elif mFlag == AppModeFlag.RESP_HELLO:
                target, args = self._recvRespHello, (mainData, addr)
            
            with self._ipAndPortToNodesCond:
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
                    case AppModeFlag.REQ_FRIEND:
                        if not self._ignoreReqFirends:
                            target, args = self._recvReqFriend, (addr,)
                    case AppModeFlag.RESP_FRIEND:
                        target, args = self._recvRespFriend, (addr,)
                    case AppModeFlag.SECOND_RESP_FRIEND:
                        target, args = self._recvSecondRespFriend, (addr,)
                    case AppModeFlag.AM_I_FRIEND:
                        target, args = self._recvAmIFirend, (addr,)
                    case AppModeFlag.RESP_AM_I_FRIEND:
                        target, args = self._recvRespAmIFirend, (addr,)
            Thread(target=target, args=args, daemon=True).start()

    def sync(self) -> None:
        with self._ipAndPortToNodesCond and self._friendsLock:
            sortedNodes:list[Node] = CustomFuncs.get(CustomFunc.GET_SORTED_NODES)(list(self._ipAndPortToNodes.values()), list(self._friends))
            if len(sortedNodes) > MAX_NODES:
                for n in sortedNodes[MAX_NODES-MAX_NODES_MARGIN:]:
                    sortedNodes.remove(n)
            self._ipAndPortToNodes.clear()
            for n in sortedNodes:
                self._ipAndPortToNodes[(n.ip, n.port)] = n
                self._ipAndPortToNodesCond.notify_all()
                if len(self._ipAndPortToNodes) < MAX_NODES-MAX_NODES_MARGIN:
                    for nI in self._getNodesSyncronized(
                        n,
                        min(NODES_LIMIT_FOR_GET, MAX_NODES-len(self._ipAndPortToNodes))
                    ):
                        if not self._ipAndPortToNodes.get((nI.ip, nI.port)):
                            self.hello(nI)
            sortedNodes = CustomFuncs.get(CustomFunc.GET_SORTED_NODES)(list(self._ipAndPortToNodes.values()))
        messages:list[tuple[NodeIdentify, AllMessageType]] = []
        messagesTree:dict[bytes, MessageForSorting] = {}
        unknows:set[tuple[NodeIdentify, bytes]] = set()
        for n in sortedNodes:
            if len(messages) >= MESSAGES_LIMIT_FOR_GET:
                break
            if m := self._getMessages(n, min(MESSAGES_LIMIT_FOR_GET - len(messages), MESSAGES_LIMIT_FOR_GET)):
                messages.extend([(n, mI) for mI in m])
        for n, m in messages:
            if isinstance(m, MyReplyMessage):
                if m.rootMessageId not in messagesTree:
                    messagesTree[m.rootMessageId] = MessageForSorting(message=None, replies=[])
                    unknows.add((n, m.messageId))
                messagesTree[m.rootMessageId].replies.append(m)
            else:
                if m.messageId not in messagesTree:
                    messagesTree[m.messageId] = MessageForSorting(message=m, replies=[])
                elif messagesTree[m.messageId].message == None:
                    messagesTree[m.messageId].message = m
                    unknows.discard((n, m.messageId))
        for n, messageId in unknows:
            if m := self._getOthersMessage(n, messageId):
                messagesTree[messageId].message = m
        with self._messagesLock:
            self._messages = messagesTree

    def _sync(self) -> None:
        logger.info("_sync thread started.")
        while True:
            self.sync(self)
            sleep(SyncIntervalSec.GLOBAL)


    def start(self, runSync:bool=True) -> None:
        Thread(target=self._recv, daemon=True).start()
        if runSync:
            Thread(target=self._sync, daemon=True).start()
        self._gossiper.start()