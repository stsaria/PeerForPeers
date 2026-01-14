from dataclasses import dataclass

from model.NodeIdentify import NodeIdentify

@dataclass(kw_only=True)
class Others:
    nodeIdentify:NodeIdentify

@dataclass(kw_only=True)
class Message:
    messageId:bytes
    content:str
    timestamp:int
    def getSqlMsg(self) -> tuple[bytes, str, int]:
        return (self.messageId, self.content, self.timestamp)

@dataclass(kw_only=True)
class ReplyMessage:
    messageId:bytes
    rootMessageId:bytes
    content:str
    timestamp:int
    def getSqlMsg(self) -> tuple[bytes, bytes, str, int]:
        return (self.messageId, self.rootMessageId, self.content, self.timestamp)

@dataclass(kw_only=True)
class OthersMessage(Message, Others):
    pass

@dataclass(kw_only=True)
class OthersReplyMessage(ReplyMessage, Others):
    pass

