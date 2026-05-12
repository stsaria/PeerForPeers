from __future__ import annotations
import asyncio
import random
import socket
from socket import AF_INET6, AF_INET
from asyncio import Lock, Task, Future
from uuid import uuid5
from logging import Logger

from P4PCore.P4PRunner import P4PRunner
from P4PCore.abstract.NetHandler import NetHandler
from P4PCore.protocol.Protocol import ENDIAN
from P4PCore.manager.SimpleImpls import SimpleKVManager, SimpleCannotOverwriteKVManager
from P4PCore.model.NodeIdentify import HashableEd25519PublicKey, NodeIdentify
from P4PCore.util.BytesCoverter import *
from P4PCore.util import BytesSplitter
from P4PCore.abstract.HasLoop import HasLoop
from P4PCore.defaultPlugin.protocol.Protocol import *
from P4PCore.defaultPlugin.protocol.ProgramProtocol import *

VERSION = 1
UUID_FLAG = uuid5(DEFAULT_PLUGIN_BASE_UUID4S["NodeGossiper"], str(VERSION))

class NodeGossiper(NetHandler, HasLoop):
    _baseRunner:P4PRunner
    _waitingPubKeyToAddr:SimpleKVManager[bytes, Future[tuple[str, int]]]
    _nodeInfoBytesToFoundTimes:SimpleCannotOverwriteKVManager[bytes, int]

    _nodeCount:int
    _nodeCountLock:Lock

    _syncerTask:Task
    
    _logger:Logger
    @classmethod
    async def create(cls, baseRunner:P4PRunner) -> "NodeGossiper":
        inst = cls()
        inst._baseRunner = baseRunner
        inst._waitingPubKeyToAddr = SimpleKVManager()
        inst._nodeInfoBytesToFoundTimes = SimpleCannotOverwriteKVManager()

        inst._nodeCount = 0
        inst._nodeCountLock = Lock()
        inst._syncerTask = None

        inst._logger = await baseRunner.getLogger(__name__)
        await inst._baseRunner._secureNet.registerHandler(UUID_FLAG, inst)

        return inst
    
    def _nodeIdentifyToBytes(self, nI:NodeIdentify) -> bytes:
        aFB = itob(
            aF := (AF_INET6 if ":" in (ip := nI.ip) else AF_INET),
            NodeGossiperPacketElementSize.IP_ADDR_FAMILY_BYTES,
            ENDIAN
        )
        ipB = socket.inet_pton(aF, ip)
        ipBA = bytearray(NodeGossiperPacketElementSize.IP_BYTES)
        ipBA[:len(ipB)] = ipB
        return (
            aFB
            +bytes(ipBA)
            +itob(nI.port, NodeGossiperPacketElementSize.PORT_BYTES, ENDIAN)
            +nI.hashableEd25519PublicKey.bytesKey
        )
    def _bytesToLightNodeIdentify(self, nIB:bytes) -> tuple[tuple[str, int], bytes] | None:
        aFB, ipB, portB, pubKeyB = BytesSplitter.split(
            nIB,
            NodeGossiperPacketElementSize.IP_ADDR_FAMILY_BYTES,
            NodeGossiperPacketElementSize.IP_BYTES,
            NodeGossiperPacketElementSize.PORT_BYTES,
            NodeGossiperPacketElementSize.ED25519_PUBLIC_KEY_BYTES
        )
        aF = btoi(aFB, ENDIAN)
        if aF == AF_INET:
            ipSize = NodeGossiperPacketElementSize.IPV4_BYTES
        elif  aF == AF_INET6:
            ipSize = NodeGossiperPacketElementSize.IPV6_BYTES
        else:
            return
        ipB = ipB[:ipSize]
        return (socket.inet_ntop(aF, ipB), btoi(portB, ENDIAN)), pubKeyB
    
    async def getNodeIdentifies(self) -> list[NodeIdentify]:
        l = []
        for nIB in await self._nodeInfoBytesToFoundTimes.getAll():
            if not (lNI := self._bytesToLightNodeIdentify(nIB)):
                continue
            l.append(
                NodeIdentify(
                    ip=lNI[0][0],
                    port=lNI[0][1],
                    hashableEd25519PublicKey=HashableEd25519PublicKey.createByBytes(lNI[1])
                )
            )
        return l

    async def addNode(self, nodeIdentify:NodeIdentify, timeOutSec:int | None = None) -> bool:
        """
        Add node for gossip targets.
        """
        return await self._pingAndAddNode(self._nodeIdentifyToBytes(nodeIdentify), timeoutSec=timeOutSec)

    async def getFutureOfWaitingAddrByPublicKey(self, publicKey:HashableEd25519PublicKey) -> Future[tuple[str, int]]:
        """
        Generate future of waiting addr by public key and return it.
        """
        future = Future()
        await self._waitingPubKeyToAddr.put(publicKey.bytesKey, future)
        return future
    async def _pingAndAddNode(self, nIB:bytes, timeoutSec:int | None = None) -> bool:
        addr, pubKeyB = self._bytesToLightNodeIdentify(nIB)
        if await self._baseRunner.pingPongNet.ping(addr, timeoutSec) is None:
            return False
        if not await self._nodeInfoBytesToFoundTimes.add(nIB, int(asyncio.get_running_loop().time())):
            return False
        if f := await self._waitingPubKeyToAddr.get(pubKeyB):
            try:
                f.set_result(addr)
            except Exception:
                pass
        return True
    async def handle(self, data:bytes, _:tuple[str, int]) -> None:
        nodes = []
        mD = data
        while len(mD) >= (
            NodeGossiperPacketElementSize.IP_ADDR_FAMILY_BYTES
            +NodeGossiperPacketElementSize.IP_BYTES
            +NodeGossiperPacketElementSize.PORT_BYTES
            +NodeGossiperPacketElementSize.ED25519_PUBLIC_KEY_BYTES
        ) and len(nodes) <= GOSSIP_MAXIMUM_NODES_FOR_A_NODE:
            nIB, mD = BytesSplitter.split(
                mD,
                NodeGossiperPacketElementSize.IP_ADDR_FAMILY_BYTES
                +NodeGossiperPacketElementSize.IP_BYTES
                +NodeGossiperPacketElementSize.PORT_BYTES
                +NodeGossiperPacketElementSize.ED25519_PUBLIC_KEY_BYTES,
                includeRest=True
            )
            nodes.append(nIB)
            async with self._nodeCountLock:
                if self._nodeCount >= GOSSIP_MAXIMUM_CONNECTIONS:
                    return
                self._nodeCount += 1
            asyncio.create_task(self._pingAndAddNode(nIB))
        
    async def _gc(self) -> None:
        now = int(asyncio.get_running_loop().time())
        for n, t in (await self._nodeInfoBytesToFoundTimes.getAll()).items():
            if (t - now) > GOSSIP_TTL_SEC:
                await self._nodeInfoBytesToFoundTimes.delete(n)
    async def _gossip(self, nodeB:bytes, selectedNodeBs:bytes) -> None:
        addr, pubKeyB = self._bytesToLightNodeIdentify(nodeB)
        if not addr in (await self._baseRunner.secureNet.getAddrs()):
            if await self._baseRunner.secureNet.hello(
                NodeIdentify(
                    ip=addr[0],
                    port=addr[1],
                    hashableEd25519PublicKey=HashableEd25519PublicKey.createByBytes(pubKeyB)
                )
            ) != self._baseRunner.secureNet.HelloResult.SUCCESS:
                return
        await self._baseRunner.secureNet.sendToSecure(
            UUID_FLAG.bytes + selectedNodeBs,
            addr
        )
    async def _syncer(self) -> None:
        while True:
            asyncio.create_task(self._gc())

            ns = list((await self._nodeInfoBytesToFoundTimes.getAll()).keys())
            nsL = len(ns)
            if nsL > 1:
                nodeBs = random.sample(
                    ns,
                    min(GOSSIP_MAXIMUM_NODES_FOR_SENDING, nsL)
                )
                selectedNodeBsForNodes = [
                    random.sample(
                        ns,
                        min(GOSSIP_MAXIMUM_NODES_FOR_A_NODE, nsL)
                    ) for _ in range(len(nodeBs))
                ]
                for nodeB, selectedNodeBs in zip(nodeBs, selectedNodeBsForNodes):
                    asyncio.create_task(self._gossip(nodeB, selectedNodeBs))
            await asyncio.sleep(GOSSIP_SYNC_SEC)
    async def begin(self) -> None:
        self._syncerTask = asyncio.create_task(self._syncer())
    async def end(self) -> None:
        if not self._syncerTask:
            return
        self._syncerTask.done()