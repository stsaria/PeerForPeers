from uuid import UUID, uuid4

from P4PCore.P4PRunner import P4PRunner
from P4PCore.abstract.NetHandler import NetHandler
from P4PCore.model.NodeIdentify import NodeIdentify
from P4PCore.model.Settings import Settings
import pytest
import asyncio

from P4PCore.core.SecureNet import SecureNet
from P4PCore.core.Net import Net
from P4PCore.model.NetConfig import NetConfig
from P4PCore.model.Ed25519Signer import Ed25519Signer
from P4PCore.protocol.Protocol import PacketFlag

class TestSecureNet:
    @pytest.mark.asyncio
    async def testSecureNetCreate(self):
        runner = await P4PRunner.create(Settings())
        assert runner.secureNet is not None

    @pytest.mark.asyncio
    async def testSecureNetRegisterHandler(self):
        runner = await P4PRunner.create(Settings())
        
        class DummyHandler(NetHandler):
            async def handle(self, data: bytes, addr: tuple[str, int]) -> None:
                pass
        
        handler = DummyHandler()
        flag = uuid4()
        result = await runner.secureNet.registerHandler(flag, handler)
        assert result is True

class TestSecureNetCommunication:
    @pytest.mark.asyncio
    async def testSecureNetHello(self):
        runner = await P4PRunner.create(Settings())
        secureNet = runner.secureNet
        await runner.begin()
        await asyncio.sleep(0.1)

        runner2 = await P4PRunner.create(Settings())
        secureNet2 = runner2.secureNet
        await runner2.begin()
        await asyncio.sleep(0.1)

        assert await secureNet2.hello(
            NodeIdentify(
                ip="127.0.0.1",
                port=secureNet.rawNet._protocolV4.transport.get_extra_info("sockname")[1],
                hashableEd25519PublicKey=runner.settings.ed25519Signer.publicKey)
            ) == runner2.secureNet.HelloResult.SUCCESS
        await asyncio.sleep(0.1)
        assert await secureNet.getAddrs()
        assert await secureNet2.getAddrs()
    @pytest.mark.asyncio
    async def testSecureNetCommunication(self):
        runner = await P4PRunner.create(Settings())
        secureNet = runner.secureNet
        class TestNetHandler(NetHandler):
            def __init__(self):
                self.receivedData = []
                self.receivedAddr = []

            async def handle(self, data:bytes, addr:tuple[str, int]) -> None:
                self.receivedData.append(data)
                self.receivedAddr.append(addr)
        handler = TestNetHandler()
        handlerFlag = uuid4()
        await secureNet.registerHandler(handlerFlag, handler)
        await runner.begin()
        await asyncio.sleep(0.1)

        runner2 = await P4PRunner.create(Settings())
        secureNet2 = runner2.secureNet
        await runner2.begin()
        await asyncio.sleep(0.1)

        netNI = NodeIdentify(
            ip="127.0.0.1",
            port=secureNet.rawNet._protocolV4.transport.get_extra_info("sockname")[1],
            hashableEd25519PublicKey=runner.settings.ed25519Signer.publicKey
        )
        await secureNet2.hello(netNI)
        await asyncio.sleep(0.1)
        
        data = b"Hello, SecureNet!"
        assert await secureNet2.sendToSecure(handlerFlag.bytes+data, netNI)
        await asyncio.sleep(0.1)
        assert handler.receivedData
        assert handler.receivedAddr
