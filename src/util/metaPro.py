from typing import Callable

def getFuncByCodeAndName(code:str, name:str) -> Callable:
    ns = {}
    exec(code, ns)
    return ns[name]