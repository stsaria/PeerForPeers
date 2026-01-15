from dataclasses import dataclass

from model.NodeIdentify import NodeIdentify
from src.util.ed25519 import Ed25519PublicKey

@dataclass(kw_only=True)
class Others:
    ed25519PubKey:Ed25519PublicKey
    ed25519Sign:bytes

@dataclass(kw_only=True)
class MyMessage:
    messageId:bytes
    content:str
    timestamp:int
    def getSqlMsg(self) -> tuple[bytes, str, int]:
        return (self.messageId, self.content, self.timestamp)

@dataclass(kw_only=True)
class MyReplyMessage:
    messageId:bytes
    rootMessageId:bytes
    content:str
    timestamp:int
    def getSqlMsg(self) -> tuple[bytes, bytes, str, int]:
        return (self.messageId, self.rootMessageId, self.content, self.timestamp)

@dataclass(kw_only=True)
class OthersMessage(MyMessage, Others):
    def getSqlMsg(self) -> tuple[bytes, bytes, str, int, bytes]:
        return (self.ed25519PubKey.public_bytes_raw(), self.messageId, self.content, self.timestamp, self.ed25519Sign)

