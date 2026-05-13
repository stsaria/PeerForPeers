from logging import Logger

from P4PCore.P4PRunner import P4PRunner
from P4PCore.defaultPlugin.core.NodeGossiper import NodeGossiper
from P4PCore.defaultPlugin.core.NodeGossiper import NodeGossiper
from P4PCore.defaultPlugin.core.PluginIdentifiesLister import PluginIdentifiesLister
from P4PCore.defaultPlugin.manager.PluginIdentifies import PluginIdentifies
from P4PCore.event.CalledBeginFunctionOfRunnerEvent import CalledBeginFunctionOfRunnerEvent
from P4PCore.event.CalledEndFunctionOfRunnerEvent import CalledEndFunctionOfRunnerEvent
from P4PCore.manager.Events import EventListener


class DefaultPluginsRunner:
    _baseRunner:P4PRunner
    _nodeGossiper:NodeGossiper
    _pluginIdentifiesManager:PluginIdentifies
    _pluginIdentifiesLister:PluginIdentifiesLister
    _logger:Logger
    @classmethod
    async def create(cls, baseRunner:P4PRunner) -> "DefaultPluginsRunner":
        inst = cls()

        inst._baseRunner = baseRunner
        inst._nodeGossiper = await NodeGossiper.create(inst._baseRunner)
        inst._pluginIdentifiesManager = PluginIdentifies()
        inst._pluginIdentifiesLister = await PluginIdentifiesLister.create(inst._baseRunner.secureNet, inst._pluginIdentifiesManager)
        inst._logger = await inst._baseRunner.getLogger(__name__)

        await inst._baseRunner.eventsManager.registerListener(inst)

        return inst
    @property
    def baseRunner(self):
        """
        A parent runner instance of this runner one.
        """
        return self._baseRunner
    @property
    def nodeGossiper(self) -> NodeGossiper:    
        """
        A node gossiper will find node addr by ed25519 public key.
        """
        return self._nodeGossiper
    @property
    def pluginIdentifiesManager(self) -> PluginIdentifies:
        """
        A manager that storage plugin identifies.
        """
        return self._pluginIdentifiesManager
    @property
    def pluginIdentifiesLister(self) -> PluginIdentifiesLister:
        """
        A plugin identifies lister for sharing available plugins.
        """
        return self._pluginIdentifiesLister
        
    @EventListener
    async def onBegin(self, _:CalledBeginFunctionOfRunnerEvent) -> None:
        await self._nodeGossiper.begin()
        self._logger.debug(f"Starting default plugins : {id(self)}")
    @EventListener
    async def onEnd(self, _:CalledEndFunctionOfRunnerEvent) -> None:
        await self._nodeGossiper.end()
        self._logger.debug(f"Ended default plugins : {id(self)}")