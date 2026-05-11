from typing import Generic, TypeVar

from P4PCore.abstract.P4PEvent import P4PEvent

T = TypeVar("T")

class NotCancelable(Exception):
    pass

class NetLikeRecvedEvent(P4PEvent, Generic[T]):
    @staticmethod
    def isAsync() -> bool:
        return True
    def __init__(self, netLikeInst:T, cancelable:bool, data:bytes, addr:tuple[str, int]):
        self._netLikeInst:T = netLikeInst
        self._cancelable:bool = cancelable
        self._data:bytes = data
        self._addr:tuple[str, int] = addr
        self._cancel:bool = False
    @property
    def netLikeInst(self) -> T:
        return self._netLikeInst
    @property
    def data(self) -> bytes:
        return self._data
    @property
    def addr(self) -> tuple[str, int]:
        return self._addr
    @property
    def cancelable(self) -> bool:
        return self._cancelable
    def cancel(self) -> None:
        if not self._cancelable:
            raise NotCancelable()
        self._cancel = True
    def isCancelled(self) -> bool:
        return self._cancel

