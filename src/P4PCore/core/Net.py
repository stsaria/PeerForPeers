from __future__ import annotations
import logging
import asyncio
from asyncio import DatagramTransport, DatagramProtocol, Semaphore, Lock
from typing import Awaitable, Callable

from P4PCore.abstract.HasLoop import HasLoop
from P4PCore.abstract.NetHandler import NetHandler
from P4PCore.interface.NetHandlerRegistry import NetHandlerRegistry
from P4PCore.manager.SimpleImpls import SimpleCannotDeleteAndOverwriteKVManager
from P4PCore.protocol.Protocol import ENDIAN, MAGIC, SOCKET_BUFFER, PacketElementSize, PacketFlag
from P4PCore.protocol.ProgramProtocol import NET_SEMAPHORE
from P4PCore.model.NetConfig import NetConfig
from P4PCore.util import BytesSplitter
from P4PCore.util.BytesCoverter import btoi

logger = logging.getLogger()

class NetServerProtocol(DatagramProtocol):
    def __init__(self, handlers:SimpleCannotDeleteAndOverwriteKVManager[PacketFlag, NetHandler], semaphore:Semaphore):
        self._handlers:SimpleCannotDeleteAndOverwriteKVManager[PacketFlag, NetHandler] = handlers
        self._sem:Semaphore = semaphore

        self.transport:DatagramTransport = None
        async def fF(data:bytes, addr:tuple[str, int]) -> bool:
            return True
        self._firewallFunc:Callable[[bytes, tuple[str, int]], Awaitable[bool]] = fF
    def connection_made(self, transport:DatagramTransport):
        self.transport = transport
    def setFirewall(self, firewallFunc:Callable[[bytes, tuple[str, int]], Awaitable[bool]]) -> None:
        self._firewallFunc = firewallFunc
    async def _run(self, data:bytes, addr:tuple[str, int]) -> None:
        if not await self._firewallFunc(data, addr):
            return
        pFlag, mainData = BytesSplitter.split(
            data,
            PacketElementSize.PACKET_FLAG,
            includeRest=True
        )
        try:
            pFlag = PacketFlag(btoi(pFlag, ENDIAN))
        except Exception:
            return
        if not (handler := await self._handlers.get(pFlag)):
            return
        async with self._sem:
            try:
                await handler.handle(mainData, addr)
            except Exception:
                logger.exception("Unhandled handler exception")
    def datagram_received(self, data:bytes, addr:tuple[str, int]) -> None:
        if len(data) > SOCKET_BUFFER:
            return
        elif data[:len(MAGIC)] != MAGIC:
            return
        asyncio.create_task(self._run(data[len(MAGIC):], addr))

class Net(NetHandlerRegistry, HasLoop):
    def __init__(self, netConfig: NetConfig) -> None:
        self._netConfig = netConfig

        self.__handlers:SimpleCannotDeleteAndOverwriteKVManager[PacketFlag, NetHandler] = SimpleCannotDeleteAndOverwriteKVManager()

        self._protocolV4:NetServerProtocol = None
        self._protocolV6:NetServerProtocol = None

        self._sem = Semaphore(NET_SEMAPHORE)
    
    def setV4Firewall(self, firewallFunc:Callable[[bytes, tuple[str, int]], Awaitable[bool]]) -> bool:
        if pV4 := self._protocolV4:
            pV4.setFirewall(firewallFunc)
    
    def setV6Firewall(self, firewallFunc:Callable[[bytes, tuple[str, int]], Awaitable[bool]]) -> bool:
        if pV6 := self._protocolV6:
            pV6.setFirewall(firewallFunc)
    
    async def registerHandler(self, packetFlag:PacketFlag, handler:NetHandler) -> bool:
        return await self.__handlers.add(packetFlag, handler)
    def sendTo(self, data:bytes, addr:tuple[str, int]) -> bool:
        if not (p := (self._protocolV6 if ':' in addr[0] else self._protocolV4)):
            return False
        elif not (t := p.transport):
            return False
        t.sendto(MAGIC+data, addr)
        return True

    def isRunning(self) -> bool:
        v4Running = v4T.is_closing() is False if ((v4 := self._protocolV4) and (v4T := v4.transport)) else False
        v6Running = v6T.is_closing() is False if ((v6 := self._protocolV6) and (v6T := v6.transport)) else False
        return v4Running or v6Running # If v4Running is False and v4is_closing() is True, v6 may be not supported by system but net is still running, so use "or" instead of "and". The opposite is a very special enviroment at present but this line may be correct for the future.

    async def begin(self) -> None:
        loop = asyncio.get_running_loop()
        
        _, self._protocolV4 = await loop.create_datagram_endpoint(
            lambda: NetServerProtocol(self.__handlers, self._sem),
            local_addr=self._netConfig.addrV4
        )
        _, self._protocolV6 = await loop.create_datagram_endpoint(
            lambda: NetServerProtocol(self.__handlers, self._sem),
            local_addr=self._netConfig.addrV6
        )
    
    async def end(self) -> None:
        if (v4 := self._protocolV4) and (v4T := v4.transport):
            v4T.close()
        if (v6 := self._protocolV6) and (v6T := v6.transport):
            v6T.close()