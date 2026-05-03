from P4PCore.defaultPlugin.core.NodeGossiper import NodeGossiper
from P4PCore.defaultPlugin.interface.IPluginIdentifiesLister import IPluginIdentifiesLister
from P4PCore.defaultPlugin.manager.PluginIdentifies import PluginIdentifies
from P4PCore.defaultPlugin.model.Node import Node
from P4PCore.interface.IP4PRunner import IP4PRunner
from P4PCore.manager.SimpleImpls import SimpleKVManager, SimpleSetManager

class IDefaultPluginsRunner:
    @classmethod
    async def create(cls, baseRunner:IP4PRunner) -> "IDefaultPluginsRunner":
        raise NotImplementedError("This method should be overridden by subclasses")
    @property
    def baseRunner(self) -> IP4PRunner:
        """
        A parent runner instance of this runner one.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
    @property
    def nodeGossiper(self) -> NodeGossiper:
        """
        A node gossiper will find node addr by ed25519 public key.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
    @property
    def nodesManager(self) -> SimpleKVManager[tuple[str, int], Node]:
        """
        A manager that maps between addr and Node instance in this instance and its subordinates instances.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
    @property
    def bannedIpsManager(self) -> SimpleSetManager[str]:
        """
        A manager that storage banned node ips.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
    @property
    def pluginIdentifiesManager(self) -> PluginIdentifies:
        """
        A manager that storage plugin identifies.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
    @property
    def pluginIdentifiesLister(self) -> IPluginIdentifiesLister:
        """
        A plugin identifies lister for sharing available plugins.
        """
        raise NotImplementedError("This method should be overridden by subclasses")