from threading import Condition, Lock, Event
from time import time

from src.interface.Manager import ObjectIndexedKVManager
from src.model.WaitingResponse import WAITING_RESPONSE_KEY, WaitingResponse
from src.protocol.ProgramProtocol import WAITING_RESPONSES_GC_SECS

ResponseValue = object 

class WaitingResponses(ObjectIndexedKVManager):
    _waitingResponses:dict[WAITING_RESPONSE_KEY, tuple[WaitingResponse, ResponseValue | None,  int]] = {}
    _waitingResponsesCond = Condition(Lock())

    @classmethod
    def _getEitherLocked(cls, key:WAITING_RESPONSE_KEY, index:int) -> WaitingResponse | ResponseValue | int | None:
        return t[index] if (t := cls._waitingResponses.get(key)) != None else None

    @classmethod
    def addKey(cls, waitingResponse:WaitingResponse) -> None:
        with cls._waitingResponsesCond:
            cls._waitingResponses[waitingResponse.getKey()] = (waitingResponse, None, int(time()))

    @classmethod
    def updateValue(cls, key:WAITING_RESPONSE_KEY, value:ResponseValue | None = None) -> ResponseValue | None:
        with cls._waitingResponsesCond:
            oldV = cls._getEitherLocked(key, 1)
            cls._waitingResponses[key][1] = value
            cls._waitingResponses[key][2] = int(time())
            cls._waitingResponsesCond.notify_all()
        return oldV
    
    @classmethod
    def delete(cls, key:WAITING_RESPONSE_KEY) -> bool:
        with cls._waitingResponsesCond:
            return cls._waitingResponses.pop(key, None) is not None

    @classmethod
    def get(cls, key:WAITING_RESPONSE_KEY) -> ResponseValue | None:
        with cls._waitingResponsesCond:
            return cls._getEitherLocked(key, 1)

    @classmethod
    def containsKey(cls, key:WAITING_RESPONSE_KEY) -> bool:
        with cls._waitingResponsesCond:
            return key in cls._waitingResponses.keys()
    
    @classmethod
    def getWaitingResponseObjByKey(cls, key:WAITING_RESPONSE_KEY) -> WaitingResponse | None:
        with cls._waitingResponsesCond:
            return cls._getEitherLocked(key, 0)
    
    @classmethod
    def waitAndGet(cls, key:WAITING_RESPONSE_KEY, timeoutMilliSec:int | None, stop:Event | None = None) -> ResponseValue | None:
        with cls._waitingResponsesCond:
            cls._waitingResponsesCond.wait_for(
                lambda: cls._getEitherLocked(key, 1) != None or (stop != None and stop.is_set()),
                timeoutMilliSec / 1000 if timeoutMilliSec != None else None
            )
            return cls._getEitherLocked(key, 1) if stop == None or not stop.is_set() else None
    
    @classmethod
    def gc(cls) -> None:
        with cls._waitingResponsesCond:
            for k,v in cls._waitingResponses.items():
                if time() - v[2] > WAITING_RESPONSES_GC_SECS:
                    cls._waitingResponses.pop(k)