from threading import Lock

from src.interface.Manager import ListManager

class BannedIps(ListManager):
    _bannedIps:set[str] = []
    _bannedIpsLock:Lock = Lock()

    @classmethod
    def add(cls, ip:str) -> bool:
        with cls._bannedIpsLock:
            if ip in cls._bannedIps: return False
            cls._bannedIps.add(ip)
        return True
    
    @classmethod
    def remove(cls, ip:str) -> None:
        try:
            with cls._bannedIps:
                cls._bannedIps.remove(ip)
        except ValueError:
            return False
        return True
    
    @classmethod
    def contains(cls, ip:str) -> bool:
        with cls._bannedIpsLock:
            return ip in cls._bannedIps