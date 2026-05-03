from asyncio import Lock
import logging
from logging import Handler, Logger

from P4PCore.abstract.HasLoop import HasLoop
from P4PCore.core.SecureNet import SecureNet
from P4PCore.event.CalledEndFunctionOfRunnerEvent import CalledEndFunctionOfRunnerEvent
from P4PCore.event.CalledBeginFunctionOfRunnerEvent import CalledBeginFunctionOfRunnerEvent
from P4PCore.interface.IP4PRunner import IP4PRunner
from P4PCore.manager.SimpleImpls import SimpleCannotDeleteAndOverwriteBiKVManager, SimpleListManager
from P4PCore.model.HashableEd25519PublicKey import HashableEd25519PublicKey
from P4PCore.model.NetConfig import NetConfig
from P4PCore.core.Net import Net
from P4PCore.manager.Events import EventListener, Events
from P4PCore.model.Settings import Settings

class P4PRunner(IP4PRunner, HasLoop):
    _settings:Settings
    _net:Net
    _secureNet:SecureNet
    _addrToEd25519PubKeys:SimpleCannotDeleteAndOverwriteBiKVManager[tuple[str, int], HashableEd25519PublicKey]
    _events:Events
    _loggerHandlers:SimpleListManager[Handler]
    _started:bool
    _startedLock:Lock
    _logger:Logger
    @classmethod
    async def create(cls, settings:Settings) -> "P4PRunner":
        inst = cls()

        inst._settings = settings
        inst._loggerHandlers = SimpleListManager()
        inst._net = Net(NetConfig(addrV4=inst._settings.v4ListeningAddr, addrV6=inst._settings.v6ListeningAddr))
        inst._secureNet = await SecureNet.create(inst._net, inst._settings.ed25519Signer)
        inst._addrToEd25519PubKeys = SimpleCannotDeleteAndOverwriteBiKVManager()
        inst._events = Events()
        inst._loggerHandlers = SimpleListManager()
        inst._started = False
        inst._startedLock = Lock()
        inst._logger = await inst.getLogger(__name__)

        await inst._secureNet.setRunner(inst)
        
        return inst
    @property
    def addrToEd25519PubkeysManager(self) -> SimpleCannotDeleteAndOverwriteBiKVManager[tuple[str, int], HashableEd25519PublicKey]:
        return self._addrToEd25519PubKeys
    @property
    def eventsManager(self) -> Events:
        return self._events
    @property
    def settings(self) -> Settings:
        return self._settings
    @settings.setter
    def settings(self, settings:Settings) -> None:
        self._settings = settings
    @property
    def secureNet(self) -> SecureNet:
        return self._secureNet
    @property
    def loggerHandlersManager(self) -> SimpleListManager[Handler]:
        return self._loggerHandlers
    async def getLogger(self, name:str) -> Logger:
        logger = logging.getLogger(name)
        logger.handlers = await self._loggerHandlers.getAll()
        return logger
    async def begin(self) -> None:
        await self._net.begin()
        await self._events.triggerEvent(CalledBeginFunctionOfRunnerEvent())
        self._logger.debug(f"Starting P4P : {id(self)}")
    async def end(self) -> None:
        await self._net.end()
        await self._events.triggerEvent(CalledEndFunctionOfRunnerEvent())
        self._logger.debug(f"Ended P4P : {id(self)}")