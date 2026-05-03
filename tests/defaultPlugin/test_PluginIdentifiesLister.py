from uuid import uuid4
import pytest

from P4PCore.P4PRunner import P4PRunner
from P4PCore.defaultPlugin.DefaultPluginsRunner import DefaultPluginsRunner
from P4PCore.model.NodeIdentify import NodeIdentify
from P4PCore.model.Settings import Settings



class TestPluginIdentifiesLister:
    @pytest.mark.asyncio
    async def testFullPluginIdentifiesCommunication(self):
        runner = await DefaultPluginsRunner.create(await P4PRunner.create(Settings()))
        await runner.baseRunner.begin()
        nI = NodeIdentify(
            ip="127.0.0.1",
            port=runner.baseRunner.secureNet.rawNet._protocolV4.transport.get_extra_info("sockname")[1],
            hashableEd25519PublicKey=runner.baseRunner.settings.ed25519Signer.publicKey
        )

        runner2 = await DefaultPluginsRunner.create(await P4PRunner.create(Settings()))
        await runner2.baseRunner.begin()

        uuid = uuid4()

        await runner.pluginIdentifiesManager.add(uuid)

        await runner2.baseRunner.secureNet.hello(nI)

        assert (uuids := await runner2.pluginIdentifiesLister.getUUIDs(nI))
        assert uuids[0] == uuid