from threading import Lock

from P4PCore.model.Ed25519Signer import Ed25519Signer

class Settings:
    def __init__(self, v4Addr:tuple[str, int] = ("127.0.0.1", 0), v6Addr:tuple[str, int] = ("127.0.0.1", 0), ed25519Signer:Ed25519Signer | None = None):
        self._v4ListeningAddr:tuple[str, int] = v4Addr
        self._v6ListeningAddr:tuple[str, int] = v6Addr
        self._ed25519Signer:Ed25519Signer = ed25519Signer or Ed25519Signer() 
        self._lock:Lock = Lock()
    @property
    def v4ListeningAddr(self) -> tuple[str, int] | None:
        with self._lock:
            return self._v4ListeningAddr
    @property
    def v6ListeningAddr(self) -> tuple[str, int] | None:
        with self._lock:
            return self._v6ListeningAddr
    @property
    def ed25519Signer(self) -> Ed25519Signer:
        with self._lock:
            return self._ed25519Signer