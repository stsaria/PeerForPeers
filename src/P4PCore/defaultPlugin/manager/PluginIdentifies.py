from uuid import UUID

from P4PCore.manager.SimpleImpls import SimpleSetManager
from P4PCore.protocol.Protocol import getMaxDataSizeOnAesEncrypted, SecurePacketElementSize
from P4PCore.defaultPlugin.protocol.Protocol import PluginsListerPacketElementSize

class PluginIdentifies(SimpleSetManager[UUID]):
    def _add(self, s:set, i:UUID) -> bool:
        if (len(s)+1)*PluginsListerPacketElementSize.PLUGIN_UUID > (
            getMaxDataSizeOnAesEncrypted()
            -SecurePacketElementSize.CONTENT_UUID
            -PluginsListerPacketElementSize.MODE_FLAG
        ):
            return False
        if i in s:
            return False
        s.add(i)
    async def add(self, item:UUID) -> bool:
        return await self.atomic(self._add, item)