from dataclasses import dataclass

from src.util.ed25519 import Ed25519PublicKey

@dataclass(frozen=True, kw_only=True)
class NodeIdentify:
    ip:str
    port:int
    ed25519PublicKey:Ed25519PublicKey
    def __hash__(self) -> int:
        return hash((self.ip, self.port, self.ed25519PublicKey.public_bytes_raw()))
    def __eq__(self, obj:"NodeIdentify") -> bool:
        if not isinstance(obj, NodeIdentify):
            return NotImplemented
        return (
            self.ip == obj.ip and
            self.port == obj.port and
            self.ed25519PublicKey.public_bytes_raw() == obj.ed25519PublicKey.public_bytes_raw()
        )
