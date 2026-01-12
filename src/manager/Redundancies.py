from threading import Lock

from src.interface.Manager import KVManager

class Redundancies(KVManager):
    _ipRedundancies:dict[str, int] = {}
    _ipRedundanciesLock:Lock = Lock()

    @classmethod
    def put(cls, ip:str, redundancy:int) -> int | None:
        with cls._ipRedundanciesLock:
            oldV = cls._ipRedundancies.get(ip)
            cls._ipRedundancies[ip] = redundancy
        return oldV
    @classmethod
    def delete(cls, ip:str) -> bool:
        with cls._ipRedundanciesLock:
            return cls._ipRedundancies.pop(ip, None)
    @classmethod
    def get(cls, ip:str) -> int | None:
        with cls._ipRedundanciesLock:
            return cls._ipRedundancies.get(ip)