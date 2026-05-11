from asyncio import Lock
import logging
from logging import Handler, Logger

from P4PCore.abstract.HasLoop import HasLoop
from P4PCore.core.PingPongNet import PingPongNet
from P4PCore.core.SecureNet import SecureNet
from P4PCore.event.CalledEndFunctionOfRunnerEvent import CalledEndFunctionOfRunnerEvent
from P4PCore.event.CalledBeginFunctionOfRunnerEvent import CalledBeginFunctionOfRunnerEvent
from P4PCore.manager.SimpleImpls import SimpleCannotDeleteAndOverwriteBiKVManager, SimpleListManager
from P4PCore.model.HashableEd25519PublicKey import HashableEd25519PublicKey
from P4PCore.model.NetConfig import NetConfig
from P4PCore.core.Net import Net
from P4PCore.manager.Events import Events
from P4PCore.model.Settings import Settings

class P4PRunner(HasLoop):
    _settings:Settings
    _net:Net
    _secureNet:SecureNet
    _pingPongNet:PingPongNet
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
        inst._events = Events()
        inst._net = Net(NetConfig(addrV4=inst._settings.v4ListeningAddr, addrV6=inst._settings.v6ListeningAddr), inst._events)
        inst._addrToEd25519PubKeys = SimpleCannotDeleteAndOverwriteBiKVManager()
        inst._secureNet = await SecureNet.create(inst._net, inst._settings.ed25519Signer, inst.getLogger, inst._addrToEd25519PubKeys, inst._events)
        inst._pingPongNet = await PingPongNet.create(inst._net, inst._events)
        inst._loggerHandlers = SimpleListManager()
        inst._started = False
        inst._startedLock = Lock()
        inst._logger = await inst.getLogger(__name__)
        
        return inst
    @property
    def addrToEd25519PubkeysManager(self) -> SimpleCannotDeleteAndOverwriteBiKVManager[tuple[str, int], HashableEd25519PublicKey]:
        """
        A manager that maps bidirectional between addr and ed25519 in this instance and its subordinates instances.
        """
        return self._addrToEd25519PubKeys
    @property
    def eventsManager(self) -> Events:
        """
        A manager that maps between event class and handler instances in this instance and its subordinates instances.
        """
        return self._events
    @property
    def settings(self) -> Settings:
        """
        Settings for P4P in this instance and its subordinates instances.
        """
        return self._settings
    @settings.setter
    def settings(self, settings:Settings) -> None:
        self._settings = settings
    @property
    def secureNet(self) -> SecureNet:
        """
        A net instance for secure communications in this instance and its subordinates instances.
        """
        return self._secureNet
    @property
    def pingPongNet(self) -> PingPongNet:
        """
        A net instance for checking if communication is possible in this instance and its subordinates instances.
        """
        return self._pingPongNet
    @property
    def loggerHandlersManager(self) -> SimpleListManager[Handler]:
        """
        A manager that stores handlers used by all logger in this instance and its subordinates instances.
        """
        return self._loggerHandlers
    async def getLogger(self, name:str) -> Logger:
        """
        Get a logger instance standard of this instnace.
        """
        logger = logging.getLogger(name)
        logger.handlers = await self._loggerHandlers.getAll()
        return logger
    async def begin(self) -> None:
        """
        Begin the instance's all.
        """
        await self._net.begin()
        await self._events.triggerEvent(CalledBeginFunctionOfRunnerEvent())
        self._logger.debug(f"Starting P4P : {id(self)}")
    async def end(self) -> None:
        """
        End the instance's all.
        """
        await self._net.end()
        await self._events.triggerEvent(CalledEndFunctionOfRunnerEvent())
        self._logger.debug(f"Ended P4P : {id(self)}")