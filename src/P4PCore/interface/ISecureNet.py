from enum import IntEnum, auto as a

from P4PCore.abstract.NetHandler import NetHandler
from P4PCore.core.Net import Net
from P4PCore.interface.NetHandlerRegistry import NetHandlerRegistry
from P4PCore.model.Ed25519Signer import Ed25519Signer
from P4PCore.model.NodeIdentify import NodeIdentify

class ISecureNet(NetHandlerRegistry):
    @classmethod
    async def create(cls, net:Net, myEd25519Signer:Ed25519Signer) -> "ISecureNet":
        raise NotImplementedError("This method should be overridden by subclasses")

    async def registerHandler(self, handler:NetHandler) -> bool:
        """
        Register a handler for handling secure packets with the given app flag.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
    def rawNet(self) -> Net:
        """
        The raw net object.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
    class HelloResult(IntEnum):
        SUCCESS = a()
        OTHER_FUNC_IS_ALREADY_TRYING_TO_CONNECT = a()
        ALREADY_CONNECTED = a()
        FAILED_FIRST_HI = a()
    async def hello(self, nodeIdentify:NodeIdentify) -> HelloResult:
        """
        Connect to the node and return the result of the connection.
        After calling this function, you can communicate with the node securely.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
    async def sendToSecure(self, data:bytes, to:tuple[str, int] | NodeIdentify) -> bool:
        """
        Send data to the node securely and return whether the sending is successful.
        This function only returns whether the sending is successful, but it does not return whether the node has received the data.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
    async def deleteNode(self, node:tuple[str, int] | NodeIdentify) -> None:
        """
        Delete node from encrypters
        Warn: If you deleted node, You can't call sendToSecure method until call hello again.
        """
        raise NotImplementedError("This method should be overridden by subclasses")