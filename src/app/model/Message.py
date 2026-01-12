from dataclasses import dataclass

@dataclass
class Message:
    messageId:bytes
    content:str
    timestamp:int
    def getSqlMsg(self) -> tuple[bytes, str, int]:
        return (self.messageId, self.content, self.timestamp)

@dataclass
class ReplyMessage:
    messageId:bytes
    rootMessageId:bytes
    content:str
    timestamp:int
    def getSqlMsg(self) -> tuple[bytes, bytes, str, int]:
        return (self.messageId, self.rootMessageId, self.content, self.timestamp)

