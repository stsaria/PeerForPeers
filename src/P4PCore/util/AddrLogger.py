from logging import Logger

class AddrLogger:
    def __init__(self, logger:Logger, sender:bool):
        self._logger = logger
        self._sender = sender
    def _conv(self, addr:tuple[str, int], msg:str) -> str:
        return ("\033[34m[S] -> " if self._sender else "\033[31m[R] <- ")+f"{addr}: {msg}\033[39m"
    def dbg(self, addr:tuple[str, int], msg:str) -> None:
        self._logger.debug(self._conv(addr, msg))
    def warn(self, addr:tuple[str, int], msg:str) -> None:
        self._logger.warning(self._conv(addr, msg))
    def exception(self, addr:tuple[str, int], msg:str) -> None:
        self._logger.exception(self._conv(addr, msg))