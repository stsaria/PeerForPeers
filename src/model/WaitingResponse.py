from dataclasses import dataclass
from typing import Hashable
from enum import Enum

from src.core.Net import Net
from src.model.NodeIdentify import NodeIdentify

WAITING_RESPONSE_KEY = tuple[str, int, Hashable, Enum | tuple[Enum], bytes | None]

@dataclass(frozen=True, kw_only=True)
class WaitingResponse:
    nodeIdentify:NodeIdentify
    waitingInst:Hashable
    waitingType:Enum
    otherInfoInKey:bytes | None = None
    otherInfo:object | None = None
    def getKey(self) -> WAITING_RESPONSE_KEY:
        return (self.nodeIdentify.ip, self.nodeIdentify.port, self.waitingType, self.otherInfoInKey)
    