from P4PCore.util.BytesCoverter import itob
import pytest
import asyncio
from P4PCore.abstract.NetHandler import NetHandler
from P4PCore.core.Net import Net, NetServerProtocol
from P4PCore.model.NetConfig import NetConfig
from P4PCore.protocol.Protocol import PacketElementSize, PacketFlag, ENDIAN

class TestNet:
    @pytest.mark.asyncio
    async def testNetCreate(self):
        config = NetConfig(addrV4=("127.0.0.1", 0), addrV6=("::1", 0))
        net = Net(config)
        assert net is not None
        assert net.isRunning() is False

    @pytest.mark.asyncio
    async def testNetBeginAndEnd(self):
        config = NetConfig(addrV4=("127.0.0.1", 0), addrV6=("::1", 0))
        net = Net(config)
        
        await net.begin()
        assert net.isRunning() is True
        
        await net.end()
        await asyncio.sleep(0.1)
        assert net.isRunning() is False

    @pytest.mark.asyncio
    async def testNetSendToWithoutStart(self):
        config = NetConfig(addrV4=("127.0.0.1", 0), addrV6=("::1", 0))
        net = Net(config)
        
        result = net.sendTo(b"test", ("127.0.0.1", 8080))
        assert result is False

    @pytest.mark.asyncio
    async def testNetSendToAfterStart(self):
        config = NetConfig(addrV4=("127.0.0.1", 0), addrV6=("::1", 0))
        net = Net(config)
        
        await net.begin()
        
        result = net.sendTo(b"test", ("127.0.0.1", 8080))
        assert result is True
        
        await net.end()
        await asyncio.sleep(0.1)


class TestNetServerProtocol:
    @pytest.mark.asyncio
    async def testProtocolSetFirewall(self):
        from P4PCore.manager.SimpleImpls import SimpleCannotDeleteAndOverwriteKVManager
        
        handlers = SimpleCannotDeleteAndOverwriteKVManager()
        sem = asyncio.Semaphore(10)
        protocol = NetServerProtocol(handlers, sem)
        
        async def firewall(data: bytes, addr: tuple[str, int]) -> bool:
            return True
        
        protocol.setFirewall(firewall)
        assert protocol._firewallFunc is not None

class TestNetHandlerCommunication:
    @pytest.mark.asyncio
    async def testFullCommunication(self):
        config = NetConfig(addrV4=("127.0.0.1", 0), addrV6=("::1", 0))
        net = Net(config)

        class TestNetHandler(NetHandler):
            def __init__(self):
                self.receivedData = []

            async def handle(self, data: bytes, _: tuple[str, int]) -> None:
                self.receivedData.append(data)
        handler = TestNetHandler()
        assert await net.registerHandler(PacketFlag.EX, handler)

        await net.begin()
        await asyncio.sleep(0.1)
        assert net.isRunning()

        net2 = Net(config)
        await net2.begin()
        await asyncio.sleep(0.1)
        assert net2.isRunning()

        testData = b"Hello, Net!"

        assert net2.sendTo(itob(PacketFlag.EX.value, PacketElementSize.PACKET_FLAG, ENDIAN) + testData, ("127.0.0.1", net._protocolV4.transport.get_extra_info("sockname")[1]))
        await asyncio.sleep(0.1)
        assert len(handler.receivedData) == 1
        assert handler.receivedData[0] == testData