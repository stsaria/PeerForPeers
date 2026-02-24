from dataclasses import dataclass
from src.util.ed25519 import Ed25519PrivateKey

@dataclass(kw_only=True)
class SecureNetConfig:
    addrV4:tuple[str, int]
    addrV6:tuple[str, int]

@dataclass(kw_only=True)
class SecureNetConfig(SecureNetConfig):
    ed25519PrivateKey:Ed25519PrivateKey