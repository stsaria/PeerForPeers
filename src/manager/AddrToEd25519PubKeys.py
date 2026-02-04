from time import time
from threading import Lock

from src.interface.Manager import CannotDeleteAndWriteKVManager
from src.util.ed25519 import Ed25519PublicKey

class AddrToEd25519PubKeys(CannotDeleteAndWriteKVManager):
    _addrToEd25519PubKeys:dict[tuple[str, int], Ed25519PublicKey] = {}
    _ed25519PubKeyToAddr:dict[bytes, tuple[str, int]] = {}
    _lock:Lock = Lock()

    @classmethod
    def put(cls, addr:tuple[str, int], publicKey:Ed25519PublicKey) -> bool:
        with cls._lock:
            if (previousKey := cls._addrToEd25519PubKeys.get(addr)) or (previousAddr := cls._ed25519PubKeyToAddr.get(publicKey.public_bytes_raw())):
                return previousKey.public_bytes_raw() == publicKey.public_bytes_raw() and previousAddr == addr
            cls._addrToEd25519PubKeys[addr] = publicKey
            cls._ed25519PubKeyToAddr[publicKey.public_bytes_raw()] = addr
        return True
    
    @classmethod
    def get(cls, addr:tuple[str, int]) -> Ed25519PublicKey | None:
        with cls._lock:
            return cls._addrToEd25519PubKeys.get(addr)
    @classmethod
    def getAddrByPublicKeyBytes(cls, publicKeyBytes:bytes) -> tuple[str, int] | None:
        with cls._lock:
            return cls._ed25519PubKeyToAddr.get(publicKeyBytes)