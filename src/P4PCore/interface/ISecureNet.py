from P4PCore.abstract.NetHandler import NetHandler
from P4PCore.core.Net import Net
from P4PCore.interface.NetHandlerRegistry import NetHandlerRegistry
from P4PCore.model.Ed25519Signer import Ed25519Signer
from P4PCore.model.NodeIdentify import NodeIdentify

class ISecureNet(NetHandlerRegistry):
    async def create(cls, net:Net, myEd25519Signer:Ed25519Signer) -> "ISecureNet":
        pass

    async def registerHandler(self, handler:NetHandler) -> bool:
        """
        Register a handler for handling secure packets with the given app flag.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
    def getNet(self) -> Net:
        """
        Get the raw net object.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
    async def hello(self, nodeIdentify:NodeIdentify) -> bool:
        """
        Connect to the node and return the result of the connection.
        After calling this function, you can communicate with the node securely.
        """
        raise NotImplementedError("This method should be overridden by subclasses")
    async def sendToSecure(self, data:bytes, nodeIdentify:NodeIdentify) -> bool:
        """
        Send data to the node securely and return whether the sending is successful.
        This function only returns whether the sending is successful, but it does not return whether the node has received the data.
        """
        raise NotImplementedError("This method should be overridden by subclasses")