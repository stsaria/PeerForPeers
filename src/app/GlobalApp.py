import logging
import statistics
from threading import Lock, Thread
from time import time
from typing import Callable
from manager.IpAndPortToEd25519PubKeys import IpToEd25519PubKeys
from manager.WaitingResponses import WaitingResponses
from model.WaitingResponse import WAITING_RESPONSE_KEY, WaitingResponse
from src.protocol.ProgramProtocol import TIME_OUT_MILLI_SEC, PING_WINDOW
from src.protocol.Protocol import *
from src.app.model.Node import Node
from app.protocol.Protocol import *
from app.protocol.ProgramProtocol import *
from src.model.NodeIdentify import NodeIdentify
from src.core.ExtendedNet import ExtendedNet
from src.core.ReliableNetController import ReliableNet
from src.core.SecureNet import SecureNet
from src.model.NetConfig import SecureNetConfig
from util import bytesSplitter, ed25519, encrypter
from util.ed25519 import Ed25519PrivateKey
from util.bytesCoverter import itob, stob

logger = logging.getLogger()

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
    def getNodes(self, nodeIdentify:NodeIdentify, nodesLimit:int) -> list[NodeIdentify]:
        waitingResponse = WaitingResponse(
            nodeIdentify,
            self,
            AppModeFlag.RESP_GET_NODES
        )
        WaitingResponses.addKey(waitingResponse)
        self._secureNet.sendToSecure(
            AppFlag.GLOBAL
            +AppModeFlag.GET_NODES
            +itob(nodesLimit, GlobalAppElementSize.NODES_LIMIT_FOR_GET),
            nodeIdentify
        )
        if r := WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC) == None:
            WaitingResponses.delete(waitingResponse)
            return False
        WaitingResponses.delete(waitingResponse)
    


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
    def _recvRespHello(self, mD:bytes, addr:tuple[str, int]) -> None:
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, AppModeFlag.RESP_HELLO)
        if not WaitingResponses.containsKey(key):
            return
        WaitingResponses.updateValue(key, mD)
    


    def _recv(self) -> None:
        for data, addr  in self._secureNet.recv():
            pFlag, mFlag, mainData = bytesSplitter.split(
                data,
                GlobalAppElementSize.APP_FLAG,
                GlobalAppElementSize.MODE_FLAG,
                includeRest=True
            )
            if pFlag != AppFlag.GLOBAL.value:
                continue
            try:
                mFlag = AppModeFlag(mFlag)
            except ValueError:
                continue
            if mFlag == AppModeFlag.HELLO:
                target, args = self._recvHello, (mainData, addr)
            elif mFlag == AppModeFlag.RESP_HELLO:
                target, args = self._recvRespHello, (mainData, addr)
            
            with self._ipAndPortToNodesLock:
                contains = self._ipAndPortToNodes.get(addr)
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
            for n in sortedNodes:
                pass

    def start(self) -> None:
        Thread(target=self._recv, daemon=True).start()
        Thread(target=self._sync, daemon=True).start()

    