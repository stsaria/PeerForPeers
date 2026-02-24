from dataclasses import dataclass

from src.app.protocol.Protocol import *
from src.model.NodeIdentify import NodeIdentify
from src.util.ed25519 import Ed25519PublicKey

@dataclass(kw_only=True)
class Node:
    ip:str
    port:int
    ed25519PublicKey:Ed25519PublicKey
    pingDelay:float
    iAmInfo:bytes
    startTimestamp:int

@dataclass(kw_only=True)
class NodeForRelay:
    ip:str
    port:int
    ed25519PublicKey:Ed25519PublicKey
    pingDelay:float

@dataclass(kw_only=True)
class Relay:
    rootNode:NodeIdentify
    recvNode:NodeIdentify
    sendNode:NodeIdentify | None
    routeType:DirectAppReleyRouteType