from uuid import UUID

from P4PCore.interface.ISecureNet import ISecureNet
from P4PCore.model.NodeIdentify import NodeIdentify

class IPluginIdentifiesLister:
    @classmethod
    async def create(cls, secureNet:ISecureNet) -> "IPluginIdentifiesLister":
        raise NotImplementedError("This method should be overridden by subclasses")
    async def getUUIDs(cls, to:tuple[str, int] | NodeIdentify) -> list[UUID]:
        """
        Get the specified node's plugin identifies.
        """
        raise NotImplementedError("This method should be overridden by subclasses")