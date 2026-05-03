from P4PCore.core.PingPongNet import PingPongNet
from P4PCore.util.BytesCoverter import itob
import pytest
import asyncio
from P4PCore.abstract.NetHandler import NetHandler
from P4PCore.core.Net import Net, NetServerProtocol
from P4PCore.model.NetConfig import NetConfig
from P4PCore.protocol.Protocol import PacketElementSize, PacketFlag, ENDIAN

class TestPingPongNet:
    @pytest.mark.asyncio
    async def testPing(self):
        config = NetConfig(addrV4=("127.0.0.1", 0), addrV6=("::1", 0))
        net = Net(config)
        await PingPongNet.create(net)
        await net.begin()

        net2 = Net(config)
        pingPongNet2 = await PingPongNet.create(net2)
        await net2.begin()

        assert not await pingPongNet2.ping(net._protocolV4.transport.get_extra_info("sockname"), timeoutSec=0.1) is None
        assert not await pingPongNet2.ping(net._protocolV6.transport.get_extra_info("sockname"), timeoutSec=0.1) is None
    @pytest.mark.asyncio
    async def testPingTimeout(self):
        config = NetConfig(addrV4=("127.0.0.1", 0), addrV6=("::1", 0))
        net = Net(config)
        await net.begin()

        net2 = Net(config)
        pingPongNet2 = await PingPongNet.create(net2)
        await net2.begin()

        assert await pingPongNet2.ping(net._protocolV4.transport.get_extra_info("sockname"), timeoutSec=0.1) is None
        assert await pingPongNet2.ping(net._protocolV6.transport.get_extra_info("sockname"), timeoutSec=0.1) is None