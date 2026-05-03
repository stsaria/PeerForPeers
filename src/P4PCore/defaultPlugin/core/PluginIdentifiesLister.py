from uuid import uuid5

from P4PCore.abstract.NetHandler import NetHandler
from P4PCore.core.SecureNet import SecureNet
from P4PCore.defaultPlugin.interface.IDefaultPluginsRunner import IDefaultPluginsRunner
from P4PCore.defaultPlugin.interface.IPluginIdentifiesLister import IPluginIdentifiesLister
from P4PCore.defaultPlugin.protocol.Protocol import *
from P4PCore.manager.WaitingResponses import WaitingResponses
from P4PCore.model.NodeIdentify import NodeIdentify
from P4PCore.model.Response import Response
from P4PCore.model.WaitingResponse import WaitingResponse
from P4PCore.model.WaitingResponseInfo import WaitingResponseInfo
from P4PCore.protocol.Protocol import ENDIAN
from P4PCore.protocol.ProgramProtocol import TIME_OUT_SEC
from P4PCore.util import BytesSplitter
from P4PCore.util.BytesCoverter import btoi, itob

VERSION = 1
UUID_FLAG = uuid5(DEFAULT_PLUGIN_BASE_UUID4S["PluginIdentifiesLister"], str(VERSION))

class PluginIdentifiesLister(IPluginIdentifiesLister, NetHandler):
    _runner:IDefaultPluginsRunner
    _secureNet:SecureNet
    _waitingResponses:WaitingResponses
    @classmethod
    async def create(cls, secureNet:SecureNet) -> "PluginIdentifiesLister":
        inst = cls()

        inst._waitingResponses = WaitingResponses()

        await secureNet.registerHandler(UUID_FLAG, inst)

        return inst
    def setRunner(self, runner:IDefaultPluginsRunner) -> None:
        self._runner = runner
        self._secureNet = self._runner.baseRunner.secureNet
    async def getUUIDs(self, to:tuple[str, int] | NodeIdentify) -> list[UUID] | None:
        if isinstance(to, NodeIdentify):
            to = to.addr
        async with self._waitingResponses.open(WaitingResponse[None, list[UUID]](WaitingResponseInfo(to))) as c:
            if not await self._secureNet.sendToSecure(
                UUID_FLAG.bytes
                +itob(PluginsListerModeFlag.GET_LIST, SimplePluginElementSize.MODE_FLAG, ENDIAN)
                +c.waitingResponse.waitingResponseInfo.identify,
                to
            ):
                return None
            if (r := await c.waitingResponse.waitAndGet(TIME_OUT_SEC)) is None:
                return None
        return r.value
    async def handle(self, data:bytes, addr:tuple[str, int]) -> None:
        mFlag, i, mD = BytesSplitter.split(
            data,
            SimplePluginElementSize.MODE_FLAG,
            SimplePluginElementSize.RESPONSE_IDENTIFY,
            includeRest=True
        )
        mFlag = btoi(mFlag, ENDIAN)

        if mFlag == PluginsListerModeFlag.GET_LIST.value:
            await self._secureNet.sendToSecure(
                UUID_FLAG.bytes
                +itob(PluginsListerModeFlag.RESP_GET_LIST, SimplePluginElementSize.MODE_FLAG, ENDIAN)
                +i
                +b"".join([uuid.bytes for uuid in await self._runner.pluginIdentifiesManager.getAll()]),
                addr
            )
        elif mFlag == PluginsListerModeFlag.RESP_GET_LIST.value:
            if not (wR := await self._waitingResponses.get((addr, i))):
                return
            uuids = []
            while len(mD) >= PluginsListerPacketElementSize.PLUGIN_UUID:
                uuidB, mD = BytesSplitter.split(
                    mD,
                    PluginsListerPacketElementSize.PLUGIN_UUID,
                    includeRest=True
                )
                try:
                    uuids.append(UUID(bytes=uuidB))
                except Exception:
                    pass
            wR.setResponse(Response(uuids))

