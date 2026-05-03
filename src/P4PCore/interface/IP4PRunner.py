from logging import Handler, Logger

from P4PCore.abstract.HasLoop import HasLoop
from P4PCore.interface.ISecureNet import ISecureNet
from P4PCore.manager.Events import Events
from P4PCore.manager.SimpleImpls import SimpleCannotDeleteAndOverwriteBiKVManager, SimpleListManager
from P4PCore.model.HashableEd25519PublicKey import HashableEd25519PublicKey
from P4PCore.model.Settings import Settings

class IP4PRunner(HasLoop):
    @classmethod
    async def create(cls, settings:Settings) -> "IP4PRunner":
        raise NotImplementedError("This method should be overridden by subclasses")
    @property
    def addrToEd25519PubkeysManager(self) -> SimpleCannotDeleteAndOverwriteBiKVManager[tuple[str, int], HashableEd25519PublicKey]:
        """
        A manager that maps bidirectional between addr and ed25519 in this instance and its subordinates instances.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
    @property
    def eventsManager(self) -> Events:
        """
        A manager that maps between event class and handler instances in this instance and its subordinates instances.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
    @property
    def settings(self) -> Settings:
        """
        Settings for P4P in this instance and its subordinates instances.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
    @settings.setter
    def settings(self, settings:Settings) -> None:
        raise NotImplementedError("This method should be overridden by subclasses")
    @property
    def secureNet(self) -> ISecureNet:
        """
        A net instance for all communications in this instance and its subordinates instances.
        But it's None before started.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
    @property
    def loggerHandlersManager(self) -> SimpleListManager[Handler]:
        """
        A manager that stores handlers used by all logger in this instance and its subordinates instances.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
    async def getLogger(self, name:str) -> Logger:
        """
        Get a logger instance standard of this instnace.
        """
        raise NotImplementedError("This method should be overridden by subclasses")

    async def begin(self) -> None:
        """
        Begin the instance's all.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
    async def end(self) -> None:
        """
        End the instance's all.
        """
        raise NotImplementedError("This method should be overridden by subclasses")