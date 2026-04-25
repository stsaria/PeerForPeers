import asyncio
from asyncio import Future

from P4PCore.interface.ISecureNet import ISecureNet
from P4PCore.abstract.P4PEvent import P4PEvent

class P4PRunnerGetSecureNetEvent(P4PEvent):
    @staticmethod
    def isAsync() -> bool:
        return False
    def __init__(self):
        self._secureNetF:Future[ISecureNet] = Future()
    def setSecureNet(self, secureNet:ISecureNet) -> None:
        if not self._secureNetF.done():
            self._secureNetF.set_result(secureNet)
    async def waitAndGet(self) -> ISecureNet:
        return await asyncio.wait_for(self._secureNetF, None)