from time import time
from threading import Lock

from src.interface.Manager import CannotDeleteAndWriteKVManager
from src.util.ed25519 import Ed25519PublicKey

class IpToEd25519PubKeys(CannotDeleteAndWriteKVManager):
    _ipAndPortToEd25519PubKeys:dict[tuple[str, int], tuple[int, Ed25519PublicKey]] = {}
    _ipAndPortToEd25519PubKeysLock:Lock = Lock()

    @classmethod
    def put(cls, addr:tuple[str, int], publicKey:Ed25519PublicKey) -> bool:
        with cls._ipAndPortToEd25519PubKeysLock:
            if previous := cls._ipAndPortToEd25519PubKeys.get(addr):
                return previous[1].public_bytes_raw() == publicKey.public_bytes_raw()
            cls._ipAndPortToEd25519PubKeys[addr] = publicKey
        return True
    
    @classmethod
    def get(cls, addr:tuple[str, int]) -> Ed25519PublicKey | None:
        with cls._ipAndPortToEd25519PubKeysLock:
            return cls._ipAndPortToEd25519PubKeys.get(addr)