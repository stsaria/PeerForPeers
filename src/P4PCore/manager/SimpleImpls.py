from asyncio import Condition, Lock, Future, TimeoutError
import asyncio
import copy
from typing import Any, Callable, TypeVar, ParamSpec, Concatenate, Generic

from P4PCore.interface.Manager import *
from P4PCore.protocol.Protocol import ANY_UNIQUE_RANDOM_BYTES_SIZE

P = ParamSpec("P")
R = TypeVar("R", covariant=True)

K = TypeVar("K")
V = TypeVar("V")
I = TypeVar("I")

class SimpleSetManager(SetManager, Generic[I]):
    def __init__(self):
        self._set:set[I] = set()
        self._setLock:Lock = Lock()
    async def add(self, item:I) -> bool:
        async with self._setLock:
            if item in self._set:
                return False
            self._set.add(item)
        return True
    async def contains(self, item:I) -> bool:
        async with self._setLock:
            return item in self._set
    async def remove(self, item:I) -> bool:
        async with self._setLock:
            if not item in self._set:
                return False
            self._set.remove(item)
        return True
    async def clear(self) -> None:
        async with self._setLock:
            self._set.clear()
    async def getAll(self) -> set[I]:
        async with self._setLock:
            return set(self._set)
    async def atomic(self, func:Callable[Concatenate[set[I], P], R], *args:P.args, **kwargs:P.kwargs) -> R:
        async with self._setLock:
            return func(self._set, *args, **kwargs)

class SimpleListManager(ListManager, Generic[I]):
    def __init__(self,):
        self._list:list[I] = []
        self._listLock:Lock = Lock()
    async def insertNext(self, value:I, index:int = -1) -> None:
        async with self._listLock:
            if index < 0:
                index = len(self._list) - abs(index)
            self._list.insert(index+1, value)
    async def change(self, index:int, value:I) -> None:
        async with self._listLock:
            self._list[index] = value
    async def get(self, index:int) -> I | None:
        async with self._listLock:
            l = len(self._list)
            if -l <= index < l:
                return self._list[index]
        return None
    async def getLength(self) -> int:
        async with self._listLock:
            return len(self._list)
    async def getIndex(self, value:I) -> int:
        async with self._listLock:
            if not value in self._list:
                return -1
            return self._list.index(value)
    async def getAll(self) -> list[I]:
        async with self._listLock:
            return self._list.copy()
    async def delete(self, index:int) -> None:
        async with self._listLock:
            del self._list[index]
    async def pop(self, index:int) -> I | None:
        async with self._listLock:
            return self._list.pop(index)
    async def deleteValue(self, value:I) -> None:
        async with self._listLock:
            self._list.remove(value)
    async def clear(self) -> None:
        async with self._listLock:
            self._list.clear()
    async def atomic(self, func:Callable[Concatenate[list[I], P], R], *args:P.args, **kwargs:P.kwargs) -> R:
        async with self._listLock:
            return func(self._list, *args, **kwargs)

class _BaseKVManager(Generic[K, V]):
    def __init__(self):
        self._dict:dict[K, V] = {}
        self._dictLock:Lock = Lock()
    async def atomic(self, func:Callable[Concatenate[dict[K, V], P], R], *args:P.args, **kwargs:P.kwargs) -> R:
        async with self._dictLock:
            return func(self._dict, *args, **kwargs)
class _BaseBiKVManager(Generic[K, V]):
    def __init__(self):
        self._dict:dict[K, V] = {}
        self._dictLock:Lock = Lock()
        self._rDict:dict[V, K] = {}
    async def atomic(self, func:Callable[Concatenate[dict[K, V], dict[V, K], P], R], *args:P.args, **kwargs:P.kwargs) -> R:
        async with self._dictLock:
            return func(self._dict, self._rDict, *args, **kwargs)
class _WriteKVMixin(WriteableKV, Generic[K, V]):
    async def put(self:_BaseKVManager[K, V], key:K, value:V) -> V | None:
        async with self._dictLock:
            oV = self._dict.get(key)
            self._dict[key] = value
        return oV
class _AddKVMixin(AddableKV, Generic[K, V]):
    async def add(self:_BaseKVManager[K, V], key:K, value:V) -> bool:
        async with self._dictLock:
            if key in self._dict:
                return self._dict[key] == value
            self._dict[key] = value
        return True
class _AddBiKVMixin(AddableBiKV, Generic[K, V]):
    async def add(self:_BaseBiKVManager[K, V], key:K, value:V) -> bool:
        async with self._dictLock:
            if (oK := self._dict.get(key)) or (oV := self._rDict.get(value)):
                return oK == key and oV == value
            self._dict[key] = value
            self._rDict[value] = key
        return True
class _ReadKVMixin(ReadableKV, Generic[K, V]):
    async def get(self:_BaseKVManager[K, V], key:K) -> V | None:
        async with self._dictLock:
            return self._dict.get(key)
    async def getAll(self:_BaseKVManager[K, V]) -> dict[K, V]:
        async with self._dictLock:
            return dict(self._dict)
    async def len(self:_BaseKVManager[K, V]) -> int:
        async with self._dictLock:
            return len(self._dict)
class _ReadBiKVMixin(ReadableBiKV, Generic[K, V]):
    async def get(self:_BaseBiKVManager[K, V], key:K) -> V | None:
        async with self._dictLock:
            return self._dict.get(key)
    async def getKey(self:_BaseBiKVManager[K, V], value:V) -> K | None:
        async with self._dictLock:
            return self._rDict.get(value)
    async def getAll(self:_BaseBiKVManager[K, V]) -> dict[K, V]:
        async with self._dictLock:
            return dict(self._dict)
    async def len(self:_BaseBiKVManager[K, V]) -> int:
        async with self._dictLock:
            return len(self._dict)
class _DeleteKVMixin(DeletableKV, Generic[K, V]):
    async def delete(self:_BaseKVManager[K, V], key:K) -> V | None:
        async with self._dictLock:
            return self._dict.pop(key, None)
    async def clear(self:_BaseKVManager[K, V]) -> None:
        async with self._dictLock:
            self._dict.clear()
class _DeleteBiKVMixin(DeletableBiKV, Generic[K, V]):
    async def delete(self:_BaseBiKVManager[K, V], key:K) -> bool:
        async with self._dictLock:
            s = key in self._dict
            self._rDict.pop(self._dict.pop(key, None), None)
            return s
    async def deleteByValue(self:_BaseBiKVManager[K, V], value:V) -> bool:
        async with self._dictLock:
            s = value in self._rDict
            self._dict.pop(self._rDict.pop(value, None), None)
            return s
    async def clear(self:_BaseBiKVManager[K, V]) -> None:
        async with self._dictLock:
            self._dict.clear()
            self._rDict.clear()

class SimpleKVManager(Generic[K, V], _BaseKVManager[K, V], _ReadKVMixin[K, V], _WriteKVMixin[K, V], _DeleteKVMixin[K, V]):
    pass
class SimpleCannotOverwriteKVManager(Generic[K, V], _BaseKVManager[K, V], _ReadKVMixin[K, V], _AddKVMixin[K, V], _DeleteKVMixin[K, V]):
    pass
class SimpleCannotDeleteKVManager(Generic[K, V], _BaseKVManager[K, V], _ReadKVMixin[K, V], _WriteKVMixin[K, V]):
    pass
class SimpleCannotDeleteAndOverwriteKVManager(Generic[K, V], _BaseKVManager[K, V], _ReadKVMixin[K, V], _AddKVMixin[K, V]):
    pass
class SimpleCannotDeleteAndOverwriteBiKVManager(Generic[K, V], _BaseBiKVManager[K, V], _ReadBiKVMixin[K, V], _AddBiKVMixin[K, V]):
    pass

class SimpleAmountLimitedTicketManager(AmountLimitedTokenManager, Generic[T]):
    def __init__(self, amountLimit:int, uniqueTokenGenerator:Callable[[], T]):
        self._amountLimit = amountLimit
        self._uniqueTokenGenerator:Callable[[], T] = uniqueTokenGenerator

        self._tokens:set[T] = set()
        self._waiters:list[Future[T]] = []
        self._lock:Lock = Lock()
    async def waitAndAllocate(self, timeoutSec:float | None=None) -> T | None:
        """First come, first served."""
        async with self._lock:
            if len(self._tokens) < self._amountLimit:
                token = self._uniqueTokenGenerator()
                self._tokens.add(token)
                return token
            fut:Future[T] = Future()
            self._waiters.append(fut)
        try:
            return await asyncio.wait_for(fut, timeoutSec)
        except TimeoutError:
            async with self._lock:
                if not fut.done():
                    fut.cancel()
                    self._waiters.remove(fut)
            return None
    async def release(self, token:T) -> None:
        async with self._lock:
            if not token in self._tokens:
                return
            self._tokens.remove(token)
            while len(self._waiters) > 0 and not self._waiters[0].done():
                fut = self._waiters.pop(0)
                if fut.done():
                    continue
                newToken = self._uniqueTokenGenerator()
                self._tokens.add(newToken)
                fut.set_result(newToken)
                break
    