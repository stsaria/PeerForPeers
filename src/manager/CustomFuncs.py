from enum import Enum
from threading import Lock
from typing import Callable
from interface.Manager import CannotDeleteKVManager
from util import metaPro

class CustomFunc(Enum):
    GET_I_AM = "getIAm"
    GET_SORTED_NODES = "getSortedNodes"
    GET_SORTED_RELAY_ROUTES = "getSortedRelayRoutes"
    GET_SORTED_MESSAGES = "getSortedMessages"
    
class CustomFuncs(CannotDeleteKVManager):
    _funcs:dict[CustomFunc, Callable] = {
        CustomFunc.GET_I_AM: lambda: b"",
        CustomFunc.GET_SORTED_NODES: lambda nodes, friends: nodes,
        CustomFunc.GET_SORTED_RELAY_ROUTES: lambda relayRoutes: relayRoutes,
        CustomFunc.GET_SORTED_MESSAGES: lambda messages: messages
    }

    @classmethod
    def put(cls, name:CustomFunc, func:Callable) -> Callable | None:
        r = cls._funcs.get(name)
        cls._funcs[name] = func
        return r
    
    @classmethod
    def get(cls, name:CustomFunc) -> Callable | None:
        return cls._funcs.get(name)
    