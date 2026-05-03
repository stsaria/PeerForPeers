import asyncio

from P4PCore.abstract.NetHandler import NetHandler
from P4PCore.core.Net import Net
from P4PCore.manager.WaitingResponses import WaitingResponses
from P4PCore.model.Response import Response
from P4PCore.model.WaitingResponse import WaitingResponse
from P4PCore.model.WaitingResponseInfo import WaitingResponseInfo
from P4PCore.protocol.Protocol import *
from P4PCore.util import BytesSplitter
from P4PCore.util.BytesCoverter import *


class PingPongNet(NetHandler):
    _net:Net
    _waitingResponses:WaitingResponses
    @classmethod
    async def create(cls, net:Net) -> "PingPongNet":
        inst = cls()

        inst._net = net
        inst._waitingResponses = WaitingResponses()

        await inst._net.registerHandler(PacketFlag.PINGPONG, inst)
        return inst
    
    async def ping(self, addr:tuple[str, int], timeoutSec:int | None = None) -> float | None:
        async with self._waitingResponses.open(
            WaitingResponse(WaitingResponseInfo(addr))
        ) as c:
            sT = asyncio.get_running_loop().time()
            if not self._net.sendTo(
                itob(PacketFlag.PINGPONG, PacketElementSize.PACKET_FLAG, ENDIAN)
                +itob(ModeFlag.PING, PacketElementSize.MODE_FLAG, ENDIAN)
                +c.waitingResponse.waitingResponseInfo.identify,
                addr
            ):
                return None
            if not await c.waitingResponse.waitAndGet(timeoutSec):
                return None
            return asyncio.get_running_loop().time() - sT
    
    async def handle(self, data:bytes, addr:tuple[str, int]) -> None:
        if len(data) != (
            PacketElementSize.MODE_FLAG
            +PacketElementSize.RESPONSE_IDENTIFY
        ):
            return
        mFlag, rI = BytesSplitter.split(
            data,
            PacketElementSize.MODE_FLAG,
            PacketElementSize.RESPONSE_IDENTIFY
        )
        try:
            mFlag = ModeFlag(btoi(mFlag, ENDIAN))
        except ValueError:
            return
        if mFlag == ModeFlag.PING:
            self._net.sendTo(
                itob(PacketFlag.PINGPONG, PacketElementSize.PACKET_FLAG, ENDIAN)
                +itob(ModeFlag.PONG, PacketElementSize.MODE_FLAG, ENDIAN)
                +rI,
                addr
            )
        elif mFlag == ModeFlag.PONG:
            wR = await self._waitingResponses.get((addr, rI))
            if wR:
                wR.setResponse(Response(None))

