from threading import Lock

from P4PCore.model.Ed25519Signer import Ed25519Signer

class Settings:
    def __init__(self, v4Addr:tuple[str, int] | None = ("127.0.0.1", 0), v6Addr:tuple[str, int] | None = None, ed25519Signer:Ed25519Signer | None = None):
        self._v4ListeningAddr:tuple[str, int] | None = v4Addr
        self._v6ListeningAddr:tuple[str, int] | None = v6Addr
        # At the time of implementation, I don't know a standard of IPv6's firewall.
        # So, Basicary I think that you shouldn't use IPv6. Maybe IPv6 on this program isn't able to work correct.
        # If you want to use IPv6, maybe you should probably do configure a router about IPv6's firewall.
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