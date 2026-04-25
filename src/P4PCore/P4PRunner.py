from P4PCore.core.SecureNet import SecureNet
from P4PCore.event.P4PRunnerGetSecureNetEvent import P4PRunnerGetSecureNetEvent

from P4PCore.event.P4PRunnerReBeginReqEvent import P4PRunnerReBeginReqEvent
from P4PCore.model.NetConfig import NetConfig
from P4PCore.core.Net import Net
from P4PCore.event.P4PRunnerBeginReqEvent import P4PRunnerBeginReqEvent
from P4PCore.event.P4PRunnerEndReqEvent import P4PRunnerEndReqEvent
from P4PCore.manager.Events import EventListener
from P4PCore.PeerForPeers import PeerForPeers

class P4PRunner:
    _net:Net
    @classmethod
    async def create(cls) -> "P4PRunner":
        inst = cls()

        s = PeerForPeers.getSettings()
        inst._net = Net(NetConfig(s.v4ListeningAddr, s.v6ListeningAddr))
        inst._secureNet = await SecureNet.create(inst._net, PeerForPeers.getAddrToEd25519PubkeysManager())
        
        return inst
    @EventListener
    async def onRunnerBeginReqEvent(self, _:P4PRunnerBeginReqEvent) -> None:
        await self._net.begin()
    @EventListener
    async def onRunnerReBeginReqEvent(self, _:P4PRunnerReBeginReqEvent) -> None:
        s = PeerForPeers.getSettings()
        self._net:Net = Net(NetConfig(s.v4ListeningAddr, s.v6ListeningAddr))
        self._secureNet:SecureNet = await SecureNet.create(self._net, PeerForPeers.getAddrToEd25519PubkeysManager())
        await self.onRunnerBeginReqEvent(P4PRunnerBeginReqEvent())
    @EventListener
    async def onRunnerEndReqEvent(self, _:P4PRunnerEndReqEvent) -> None:
        await self._net.end()
    @EventListener
    def onRunnerGetSecureNetEvent(self, e:P4PRunnerGetSecureNetEvent) -> None:
        e.setSecureNet(self._secureNet)