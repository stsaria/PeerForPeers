import asyncio
from asyncio import Lock, Task
from dataclasses import dataclass
from logging import Logger
import os
import random

from P4PCore.core.PingPongNet import PingPongNet
from P4PCore.manager.SimpleImpls import SimpleKVManager
from P4PCore.model.NodeIdentify import NodeIdentify

from P4PCore.defaultPlugin.DefaultPluginsRunner import DefaultPluginsRunner
from P4PCore.defaultPlugin.protocol.Protocol import NodeGossiperPacketElementSize
from P4PCore.util import BytesSplitter

@dataclass(kw_only=True)
class SimpleNodesSettings:
    syncTimeSec:float = 7
    sampleOfNodesOnSyncing:int = 10
    maxNodes:int = 60
    backupFileName:str | None = None

class SimpleNodesStorager:
    _runner:DefaultPluginsRunner
    _pingPongNet:PingPongNet
    _settings:SimpleNodesSettings
    _logger:Logger

    _nodesAndCommunicatable:SimpleKVManager[NodeIdentify, bool]

    _syncerTask:Task

    _saverLock:Lock
    @classmethod
    async def create(cls, runner:DefaultPluginsRunner, settings:SimpleNodesSettings):
        inst = cls()
        
        inst._runner = runner
        inst._pingPongNet = await PingPongNet.create(inst._runner.baseRunner.secureNet.rawNet, inst._runner.baseRunner.eventsManager)
        inst._settings = settings
        inst._logger = await inst._runner.baseRunner.getLogger(__name__)

        inst._nodesAndCommunicatable = SimpleKVManager()

        inst._syncerTask = None
        
        inst._saverLock = Lock()

        return inst
    async def loadFromFile(self, fileName:str) -> None:
        if not os.path.isfile(fileName):
            return
        async with self._saverLock:
            with open(fileName, mode="rb") as f:
                b = f.read()
            nIBSize = (
                NodeGossiperPacketElementSize.IP_ADDR_FAMILY_BYTES
                +NodeGossiperPacketElementSize.IP_BYTES
                +NodeGossiperPacketElementSize.PORT_BYTES
                +NodeGossiperPacketElementSize.ED25519_PUBLIC_KEY_BYTES
            )
            while b >= nIBSize:
                nIB, b = BytesSplitter.split(b, nIBSize, includeRest=True)
                nI = self._runner.nodeGossiper._bytesToLightNodeIdentify(nIB)
                self._nodesAndCommunicatable.put(nI, False)
    async def saveToFile(self, fileName:str) -> None:
        async with self._saverLock:
            nodes = self._nodesAndCommunicatable.getAll()
            nodesBA = bytearray()
            for nI in nodes:
                nodesBA.extend(self._runner.nodeGossiper._nodeIdentifyToBytes(nI))
            with open(fileName, mode="wb") as f:
                f.write(nodesBA)
    async def addNode(self, nodeIdentify:NodeIdentify) -> bool:
        if await self._nodesAndCommunicatable.len()+1 > self._settings.maxNodes:
            return False
        hR = self._runner.baseRunner.secureNet.HelloResult
        r = await self._runner.baseRunner.secureNet.hello()
        if r == hR.ALREADY_CONNECTED:
            return True
        elif r != hR.SUCCESS:
            return False
        await self._runner.nodeGossiper.addNode(nodeIdentify)
        await self._nodesAndCommunicatable.put(nodeIdentify, True)
        return True
    async def _syncer(self) -> None:
        while True:
            checkingNodes = dict(random.sample(list((ns := await self._nodesAndCommunicatable.getAll()).items()), min(ns, self._settings.sampleOfNodesOnSyncing)))
            for nI, cable in checkingNodes:
                r = await self.addNode(nI)
                if not r and cable:
                    await self._nodesAndCommunicatable.delete(nI)
            for nI in self._runner.nodeGossiper.getNodeIdentifies():
                await self.addNode(nI)
            if not (fN := self._settings.backupFileName) is None:
                await self.saveToFile(fN)
            await asyncio.sleep(self._settings.syncTimeSec)
    async def begin(self) -> None:
        self._syncerTask = asyncio.create_task(self._syncer())
    async def end(self) -> None:
        if not self._syncerTask:
            return
        self._syncerTask.done()