from typing import Any, Protocol, TypeVar

T = TypeVar("T")
K = TypeVar("K")
O = TypeVar("O")
V = TypeVar("V")

class ListManager(Protocol[T]):
    @classmethod
    def add(cls, item:T) -> bool: ... # return !contains
    @classmethod
    def remove(cls, item:T) -> bool: ...
    @classmethod
    def contains(cls, item:T) -> bool: ...

class CannotRemoveListManager(Protocol[T]):
    @classmethod
    def add(cls, item:T) -> bool: ... # return !contains
    @classmethod
    def contains(cls, item:T) -> bool: ...


class KVManager(Protocol[K, V]):
    @classmethod
    def put(cls, key:K, value:V) -> V | None: ...
    @classmethod
    def delete(cls, key:K) -> bool: ...
    @classmethod
    def get(cls, key:K) -> V | None: ...

class ObjectIndexedKVManager(Protocol[K, O, V]):
    @classmethod
    def addKey(cls, object:O) -> bool: ... # return !contains
    @classmethod
    def updateValue(cls, key:K, value:V) -> V | None: ...
    @classmethod
    def delete(cls, key:K) -> bool: ...
    @classmethod
    def get(cls, key:K) -> V | None: ...
    @classmethod
    def containsKey(cls, key:K) -> bool: ...
    @classmethod
    def waitAndGet(cls, key:K, timeoutMilliSec:int) -> V | None: ...

class CannotDeleteKVManager(Protocol[K, V]):
    @classmethod
    def put(cls, *key:K, value:V) -> V | None: ...
    @classmethod
    def get(cls, key:K) -> V | None: ...

class CannotDeleteAndWriteKVManager(Protocol[K, V]):
    @classmethod
    def put(cls, *key:K, value:V) -> bool: ...
    @classmethod
    def get(cls, key:K) -> V | None: ...

class MinimalKVManager(Protocol[K, V]):
    @classmethod
    def put(cls, key:K, value:V) -> Any: ...
    @classmethod
    def delete(cls, key:K) -> Any: ...
    @classmethod
    def get(cls, key:K) -> V | Any: ...

class TicketingManager(Protocol[T]):
    @classmethod
    def issueTicket(cls) -> T: ...
    @classmethod
    def dropTicket(cls, ticket:T) -> None: ...