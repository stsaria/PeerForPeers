from enum import Enum
from threading import Lock
from typing import Callable
from interface.Manager import CannotDeleteKVManager

class CustomFunc(Enum):
    GET_I_AM = "getIAm"
    GET_SORTED_NODES = "getSortedNodes"
    GET_SORTED_RELAY_ROUTES = "getSortedRelayRoutes"
    
class CustomFuncs(CannotDeleteKVManager):
    _funcs:dict[CustomFunc, Callable] = {
        CustomFunc.GET_I_AM: lambda: b"",
        CustomFunc.GET_SORTED_NODES: lambda nodes, friends: nodes,
        CustomFunc.GET_SORTED_RELAY_ROUTES: lambda relayRoutes: relayRoutes
    }

    @classmethod
    def put(cls, name:CustomFunc, func:Callable) -> Callable | None:
        r = cls._funcs.get(name)
        cls._funcs[name] = func
        return r
    
    @classmethod
    def get(cls, name:CustomFunc) -> Callable | None:
        return cls._funcs.get(name)
    