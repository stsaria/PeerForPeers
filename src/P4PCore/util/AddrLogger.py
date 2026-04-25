from logging import Logger

class AddrLogger:
    def __init__(self, logger:Logger, sender:bool):
        self._logger = logger
        self._sender = sender
    def dbg(self, addr:tuple[str, int], msg:str):
        self._logger.debug(("\033[34m[S] ->" if self._sender else "\033[31m[R] <-")+f"{addr}: {msg}\033[39m")