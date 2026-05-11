import asyncio
from typing import Callable, Generic, Type
import typing

from P4PCore.manager.SimpleImpls import SimpleCannotDeleteKVManager
from P4PCore.abstract.P4PEvent import P4PEvent

_pendingInsts:list[object] = []

class Events:
    def __init__(self):
        self._events:SimpleCannotDeleteKVManager[Type[P4PEvent], Callable] = SimpleCannotDeleteKVManager()
        for inst in _pendingInsts:
            asyncio.run(self.registerListener(inst))
    async def registerListener(self, inst:object) -> None:
        """
        Register an instance to listen to events.
        
        The instance in argument should have methods decorated with @EventListener, and the type hint of the first argument of these methods should be a subclass of P4PEvent.
        """
        for n in dir(inst):
            m = getattr(inst, n)
            if not hasattr(m, "_isAEventListener"):
                continue
            for aN, aT in typing.get_type_hints(m).items():
                if aN == "return":
                    continue
                elif not issubclass(aT, P4PEvent):
                    continue
                await self._events.atomic(lambda d: d.setdefault(aT, set()).add(m))
    async def triggerEvent(self, event:P4PEvent) -> None:
        """
        Trigger an event. All the listeners registered to listen to this type of event will be called.
        """
        if (eT := getattr(event, "__orig_class__", None)) is None:
            eT = type(event)
        if event.isAsync():
            await asyncio.gather(*(callback(event) for callback in await self._events.get(type(event)) or set()))
        else:
            for callback in await self._events.get(eT) or set():
                callback(event)

def EventListener(func:Callable) -> Callable:
    setattr(func, "_isAEventListener", True)
    return func