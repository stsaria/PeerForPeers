from enum import Enum
from typing import Callable

from interface.Manager import CannotDeleteKVManager

class CustomFunc(Enum):
    GET_I_AM = "getIAm"
    GET_SORTED_NODES = "getSortedNodes"
    GET_SORTED_RELAY_ROUTES = "getSortedRelayRoutes"
    GET_SORTED_MESSAGES = "getSortedMessages"
    WILL_PASS_PACKET_FOR_ALL = "willPassPacketForAll"
    WILL_PASS_PACKET_FOR_GLOBAL_APP = "willPassPacketForGlobalApp"
    WILL_PASS_PACKET_FOR_DIRECT_APP = "willPassPacketForDirectApp"
    
class CustomFuncs(CannotDeleteKVManager):
    _funcs:dict[CustomFunc, Callable] = {
        CustomFunc.GET_I_AM: lambda: b"",
        CustomFunc.GET_SORTED_NODES: lambda nodes, friends: nodes,
        CustomFunc.GET_SORTED_RELAY_ROUTES: lambda relayRoutes: relayRoutes,
        CustomFunc.GET_SORTED_MESSAGES: lambda messages: messages,
        CustomFunc.WILL_PASS_PACKET_FOR_ALL: lambda addr, data: True,
        CustomFunc.WILL_PASS_PACKET_FOR_GLOBAL_APP: lambda addr, appFlag, modeFlag, maindData: True,
        CustomFunc.WILL_PASS_PACKET_FOR_DIRECT_APP: lambda addr, appFlag, modeFlag, maindData: True,
    }

    @classmethod
    def put(cls, name:CustomFunc, func:Callable) -> Callable | None:
        r = cls._funcs.get(name)
        cls._funcs[name] = func
        return r
    
    @classmethod
    def get(cls, name:CustomFunc) -> Callable | None:
        return cls._funcs.get(name)
    