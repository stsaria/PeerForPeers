from uuid import UUID, uuid4

from P4PCore.abstract.NetHandler import NetHandler
from P4PCore.model.NodeIdentify import NodeIdentify
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
        config = NetConfig(addrV4=("127.0.0.1", 0), addrV6=("::1", 0))
        net = Net(config)
        signer = Ed25519Signer()
        
        secureNet = await SecureNet.create(net, signer)
        assert secureNet is not None

    @pytest.mark.asyncio
    async def testSecureNetRegisterHandler(self):
        from P4PCore.abstract.NetHandler import NetHandler
        from uuid import uuid4
        
        config = NetConfig(addrV4=("127.0.0.1", 0), addrV6=("::1", 0))
        net = Net(config)
        signer = Ed25519Signer()
        
        secureNet = await SecureNet.create(net, signer)
        
        class DummyHandler(NetHandler):
            async def handle(self, data: bytes, addr: tuple[str, int]) -> None:
                pass
        
        handler = DummyHandler()
        flag = uuid4()
        result = await secureNet.registerHandler(flag, handler)
        assert result is True

class TestSecureNetCommunication:
    @pytest.mark.asyncio
    async def testSecureNetHello(self):
        config = NetConfig(addrV4=("127.0.0.1", 0), addrV6=("::1", 0))
        net = Net(config)
        signer = Ed25519Signer()

        secureNet = await SecureNet.create(net, signer)
        await net.begin()
        await asyncio.sleep(0.1)

        net2 = Net(config)
        signer2 = Ed25519Signer()
        
        secureNet2 = await SecureNet.create(net2, signer2)
        await net2.begin()
        await asyncio.sleep(0.1)

        assert await secureNet2.hello(NodeIdentify(ip="127.0.0.1", port=net._protocolV4.transport.get_extra_info("sockname")[1], hashableEd25519PublicKey=signer.publicKey)) == secureNet2.HelloResult.SUCCESS
        await asyncio.sleep(0.1)
        assert await secureNet.getAddrs()
        assert await secureNet2.getAddrs()
    @pytest.mark.asyncio
    async def testSecureNetCommunication(self):
        config = NetConfig(addrV4=("127.0.0.1", 0), addrV6=("::1", 0))
        net = Net(config)
        signer = Ed25519Signer()

        secureNet = await SecureNet.create(net, signer)
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
        await net.begin()
        await asyncio.sleep(0.1)

        net2 = Net(config)
        signer2 = Ed25519Signer()
        secureNet2 = await SecureNet.create(net2, signer2)
        await net2.begin()
        await asyncio.sleep(0.1)

        netNI = NodeIdentify(ip="127.0.0.1", port=net._protocolV4.transport.get_extra_info("sockname")[1], hashableEd25519PublicKey=signer.publicKey)
        await secureNet2.hello(netNI)
        await asyncio.sleep(0.1)
        
        data = b"Hello, SecureNet!"
        assert await secureNet2.sendToSecure(handlerFlag.bytes+data, netNI)
        await asyncio.sleep(0.1)
        assert handler.receivedData
        assert handler.receivedAddr
