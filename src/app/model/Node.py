from dataclasses import dataclass

from src.util.ed25519 import Ed25519PublicKey

@dataclass(kw_only=True)
class Node:
    ip:str
    port:int
    ed25519PublicKey:Ed25519PublicKey
    pingDelay:float
    iAmInfo:bytes
    startTimestamp:int