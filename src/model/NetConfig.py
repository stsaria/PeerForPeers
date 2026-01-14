from dataclasses import dataclass
from src.util.ed25519 import Ed25519PrivateKey

@dataclass(kw_only=True)
class NetConfig:
    addrV4:tuple[str, int]
    addrV6:tuple[str, int]
    buffer:int

@dataclass(kw_only=True)
class SecureNetConfig(NetConfig):
    ed25519PrivateKey:Ed25519PrivateKey