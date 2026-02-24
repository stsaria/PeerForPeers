import os
from threading import Lock, Thread
from time import time
from typing import Generator

from manager.CustomFuncs import CustomFunc, CustomFuncs
from src.manager.Redundancies import Redundancies
from src.manager.WaitingResponses import WaitingResponses
from src.model.WaitingResponse import WaitingResponse
from src.protocol.ProgramProtocol import *
from src.model.NodeIdentify import NodeIdentify
from src.core.Net import Net
from src.model.NetConfig import SecureNetConfig
from src.protocol.Protocol import *
from src.util import redundancyCalc
from src.util.bytesCoverter import itob

class ExtendedNet(Net):
    _shareVars = ["_netConfig", "_sock", "_gens", "_gensLock", "_started", "_startedLock"]
    def __init__(self, netConfig:SecureNetConfig):
        super().__init__(netConfig)

        self._started = False
        self._startedLock = Lock()

        self._gens:set[Generator[tuple[bytes, tuple[str, int]], None, None]] = set()
        self._gensLock:Lock = Lock()
    def sendTo(self, data:bytes, node:NodeIdentify | tuple[str, int]) -> None:
        addr = (node.ip, node.port) if isinstance(node, NodeIdentify) else node
        for _ in range(
            r if (r := Redundancies.get(addr[0])) else PING_MILLI_SEC_REDUNDANCIES[0][1]
        ): 
            super().sendTo(data, addr)
    def ping(self, node:NodeIdentify | tuple[str, int]) -> float | None:
        sid = os.urandom(ANY_SESSION_ID_SIZE)
        waitingResponse = WaitingResponse(
            nodeIdentify=
                node
                if isinstance(node, NodeIdentify) else
                NodeIdentify(
                    node[0],
                    node[1],
                    b""
                ),
            waitingInst=self,
            waitingType=PacketModeFlag.PONG,
            otherInfoInKey=sid
        )
        WaitingResponses.addKey(waitingResponse)
        st = time()
        self.sendTo(
            (
                itob(PacketFlag.SECURE, SecurePacketElementSize.PACKET_FLAG)
                +itob(PacketModeFlag.PING, SecurePacketElementSize.MODE_FLAG)
                +sid
            ),
            node
        )
        if WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC) == None:
            WaitingResponses.delete(waitingResponse)
            return None
        WaitingResponses.delete(waitingResponse)
        return time() - st
    def pingAndSetRedundancy(self, nodeIdentify:NodeIdentify, dontUpdateIfContains:bool=True) -> bool:
        if Redundancies.get(nodeIdentify.ip) != None and dontUpdateIfContains: return True
        pings = []
        for _ in range(PING_WINDOW):
            if l := self.ping(nodeIdentify):
                pings.append(l)
        if len(pings) <= 0:
            return False
        redundancy = redundancyCalc.calcRedundancyByPing(
            PING_MILLI_SEC_REDUNDANCIES,
            pings,
            PING_CALC_TRIM_RATIO
        )
        Redundancies.put(nodeIdentify.ip, redundancy)
        return True
    def _recvLoop(self) -> None:
        for data, addr in super().recv():
            if not CustomFuncs.get(CustomFunc.WILL_PASS_PACKET_FOR_ALL)(addr, data):
                continue

            if data[
                :PacketElementSize.PACKET_FLAG
                +PacketElementSize.MODE_FLAG
            ] == PacketFlag.PLAIN+PacketModeFlag.PING:
                self.sendTo(
                    PacketFlag.PLAIN
                    +PacketModeFlag.PONG
                    +data[
                        PacketElementSize.PACKET_FLAG
                        +PacketElementSize.MODE_FLAG:
                    ],
                    addr
                )
            elif data[
                :PacketElementSize.PACKET_FLAG
                +PacketElementSize.MODE_FLAG
            ] == PacketFlag.PLAIN+PacketModeFlag.PONG:
                if WaitingResponses.containsKey(
                    (k := 
                        (addr[0],
                         addr[1],
                         self,
                         PacketModeFlag.RESP_HELLO,
                         data[
                             PacketElementSize.PACKET_FLAG
                            +PacketElementSize.MODE_FLAG:
                         ]
                        )
                    )
                ): WaitingResponses.updateValue(k, 1)

            if not self._started:
                with self._gensLock:
                    for gen in self._gens:
                        gen.close()
                        self._gens.remove(gen)
                break
            with self._gensLock:
                for gen in self._gens:
                    gen.send((data, addr))
    def stop(self) -> None:
        with self._startedLock:
            if not self._started:
                return
            self._started = False
    def startRecvAndGetStream(self) -> None:
        with self._startedLock:
            if self._started:
                return
            self._started = True
        Thread(target=self._recvLoop, daemon=True).start()
    def recv(self) -> Generator[tuple[bytes, tuple[str, int]], None, None]:
        gen = yield
        with self._gensLock:
            self._gens.add(gen)
        return gen
    def _closeRecv(self, gen:Generator[tuple[bytes, tuple[str, int]], None, None]) -> None:
        with self._gensLock:
            self._gens.remove(gen)
        gen.close()
    @classmethod
    def getShareObj(cls, obj:"ExtendedNet") -> "ExtendedNet":
        newObj = cls.__new__(cls)
        for v in ExtendedNet._shareVars:
            newObj.__dict__[v] = obj.__dict__[v]
        return newObj