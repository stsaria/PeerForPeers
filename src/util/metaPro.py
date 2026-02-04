from typing import Callable

def getFuncByCodeAndName(self, code:str, name:str) -> Callable:
    ns = {}
    exec(code, ns)
    return ns[name]