import socket

import pytest
import asyncio

from P4PCore.P4PRunner import P4PRunner
from P4PCore.core.PingPongNet import PingPongNet
from P4PCore.defaultPlugin.DefaultPluginsRunner import DefaultPluginsRunner
from P4PCore.defaultPlugin.core.NodeGossiper import NodeGossiper
from P4PCore.model.NodeIdentify import NodeIdentify
from P4PCore.model.Settings import Settings

class TestNodeGossiper:
    @pytest.mark.asyncio
    async def testAddNodeStoresNodeInfoWhenPingSucceeds(self):
        settings = Settings()
        runner = await P4PRunner.create(settings)
        await runner.begin()

        runner2 = await P4PRunner.create(Settings())
        await runner2.begin()
        await PingPongNet.create(runner2.secureNet.rawNet)

        gossiper = await NodeGossiper.create(runner.secureNet)

        nodeIdentify = NodeIdentify(
            ip="127.0.0.1",
            port=runner2.secureNet.rawNet._protocolV4.transport.get_extra_info("sockname")[1],
            hashableEd25519PublicKey=settings.ed25519Signer.publicKey,
        )

        assert await gossiper.addNode(nodeIdentify)
        all_nodes = await gossiper._nodeInfoBytesToFoundTimes.getAll()
        assert len(all_nodes) == 1
        assert any(k.endswith(settings.ed25519Signer.publicKey.bytesKey) for k in all_nodes)

    @pytest.mark.asyncio
    async def testAddNodeReturnsNoneWhenPingFails(self):
        settings = Settings()
        runner = await P4PRunner.create(settings)
        await runner.begin()

        gossiper = await NodeGossiper.create(runner.secureNet)

        nodeIdentify = NodeIdentify(
            ip="127.0.0.1",
            port=8080,
            hashableEd25519PublicKey=settings.ed25519Signer.publicKey,
        )

        assert not await gossiper.addNode(nodeIdentify)
        assert await gossiper._nodeInfoBytesToFoundTimes.getAll() == {}

    @pytest.mark.asyncio
    async def testFindNode(self):
        runners:list[DefaultPluginsRunner] = []
        for _ in range(3):
            r = await DefaultPluginsRunner.create(await P4PRunner.create(Settings()))
            await r.baseRunner.begin()
            await r.nodeGossiper.end()
            runners.append(r)
        ports:list[int] = []
        for r in runners:
            rN = r.baseRunner.secureNet.rawNet
            ports.append(
                rN._protocolV4.transport.get_extra_info("sockname")[1]
            )
        await asyncio.sleep(0.1)

        f = await runners[0].nodeGossiper.getFutureOfWaitingAddrByPublicKey(
            runners[2].baseRunner.settings.ed25519Signer.publicKey
        )

        nG2:NodeGossiper = runners[1]._nodeGossiper
        await nG2._gossip(
            nG2._nodeIdentifyToBytes(
                NodeIdentify(
                    ip="127.0.0.1",
                    port=runners[0].baseRunner.secureNet.rawNet._protocolV4.transport.get_extra_info("sockname")[1],
                    hashableEd25519PublicKey=runners[0].baseRunner.settings.ed25519Signer.publicKey
                )
            ),
            nG2._nodeIdentifyToBytes(
                NodeIdentify(
                    ip="127.0.0.1",
                    port=runners[2].baseRunner.secureNet.rawNet._protocolV4.transport.get_extra_info("sockname")[1],
                    hashableEd25519PublicKey=runners[2].baseRunner.settings.ed25519Signer.publicKey
                )
            )
        )
        
        assert not await asyncio.wait_for(f, 3) is None
