from logging import Logger

from P4PCore.P4PRunner import P4PRunner
from P4PCore.defaultPlugin.core.NodeGossiper import NodeGossiper
from P4PCore.defaultPlugin.interface.IDefaultPluginsRunner import IDefaultPluginsRunner
from P4PCore.defaultPlugin.core.NodeGossiper import NodeGossiper
from P4PCore.defaultPlugin.core.PluginIdentifiesLister import PluginIdentifiesLister
from P4PCore.defaultPlugin.manager.PluginIdentifies import PluginIdentifies
from P4PCore.defaultPlugin.model.Node import Node
from P4PCore.event.CalledBeginFunctionOfRunnerEvent import CalledBeginFunctionOfRunnerEvent
from P4PCore.event.CalledEndFunctionOfRunnerEvent import CalledEndFunctionOfRunnerEvent
from P4PCore.manager.Events import EventListener
from P4PCore.manager.SimpleImpls import SimpleKVManager, SimpleSetManager


class DefaultPluginsRunner(IDefaultPluginsRunner):
    _baseRunner:P4PRunner
    _nodeGossiper:NodeGossiper
    _nodesManager:SimpleKVManager[tuple[str, int], Node]
    _bannedIpsManager:SimpleSetManager[str]
    _pluginIdentifiesManager:PluginIdentifies
    _pluginIdentifiesLister:PluginIdentifiesLister
    _logger:Logger
    @classmethod
    async def create(cls, baseRunner:P4PRunner) -> "DefaultPluginsRunner":
        inst = cls()

        inst._baseRunner = baseRunner
        inst._nodeGossiper = await NodeGossiper.create(inst._baseRunner.secureNet)
        inst._nodesManager = SimpleKVManager()
        inst._bannedIpsManager = SimpleSetManager()
        inst._pluginIdentifiesManager = PluginIdentifies()
        inst._pluginIdentifiesLister = await PluginIdentifiesLister.create(inst._baseRunner.secureNet)
        inst._logger = await inst._baseRunner.getLogger(__name__)

        async def defaultNetFirewall(_:bytes, addr:tuple[str, int]) -> bool:
            return not await inst._bannedIpsManager.contains(addr[0])
        
        inst._baseRunner.secureNet.rawNet.setV4Firewall(defaultNetFirewall)
        inst._baseRunner.secureNet.rawNet.setV6Firewall(defaultNetFirewall)

        await inst._baseRunner.eventsManager.registerEvent(inst)

        inst._pluginIdentifiesLister.setRunner(inst)

        return inst
    @property
    def baseRunner(self):
        return self._baseRunner
    @property
    def nodeGossiper(self) -> NodeGossiper:    
        return self._nodeGossiper
    @property
    def nodesManager(self) -> SimpleKVManager[tuple[str, int], Node]:
        return self._nodesManager
    @property
    def bannedIpsManager(self) -> SimpleSetManager[str]:
        return self._bannedIpsManager
    @property
    def pluginIdentifiesManager(self) -> PluginIdentifies:
        return self._pluginIdentifiesManager
    @property
    def pluginIdentifiesLister(self) -> PluginIdentifiesLister:
        return self._pluginIdentifiesLister
    
    @EventListener
    async def onBegin(self, _:CalledBeginFunctionOfRunnerEvent) -> None:
        await self._nodeGossiper.begin()
        self._logger.debug(f"Starting default plugins : {id(self)}")
    @EventListener
    async def onEnd(self, _:CalledEndFunctionOfRunnerEvent) -> None:
        await self._nodeGossiper.end()
        self._logger.debug(f"Ended default plugins : {id(self)}")