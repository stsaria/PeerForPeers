from dataclasses import dataclass, field
from enum import Enum
import math
from threading import Lock
from typing import Any, Generator

from src.protocol.Protocol import *
from src.model.EncryptCollection import EncryptCollection
from src.util.ed25519 import Ed25519PublicKey

class ReliableSessionElementKey(Enum):
    ENCRYPT_COLLECTION = 1
    CHUNK_PACKETS = 2
    CHUNKS = 3
    NOW_CHUNK = 4

@dataclass(kw_only=True)
class ReliableSession:
    sessionId: bytes
    recvGenerator: Generator[bytes, None, bool]
    size: int
    otherPartyEd25519PublicKey: Ed25519PublicKey

    _encryptCollection: EncryptCollection | None = None
    _chunkPackets: dict[int, bytes] = field(default_factory=dict)

    _chunks: int | None = None
    _nowChunk: int = 1

    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def calcChunks(self) -> None:
        with self._lock:
            self._chunks = math.ceil(
                self.size / (
                    SOCKET_BUFFER
                    -ReliablePacketElementSize.PACKET_FLAG
                    -ReliablePacketElementSize.MODE_FLAG
                    -ReliablePacketElementSize.SEQ_AND_CHUNK_COUNT
                )
            )

    def sendGen(self, d:bytes) -> None:
        with self._lock:
            self.recvGenerator.send(d)
    
    def closeGen(self) -> None:
        with self._lock:
            self.recvGenerator.close()
    
    def throwGen(self, exp:Exception) -> None:
        with self._lock:
            self.recvGenerator.throw(exp)

    def get(self, *elementKey:ReliableSessionElementKey) -> list[Any] | Any:
        r = []
        with self._lock:
            for k in elementKey:
                match k:
                    case ReliableSessionElementKey.ENCRYPT_COLLECTION:
                        r.append(self._encryptCollection)
                    case ReliableSessionElementKey.CHUNK_PACKETS:
                        r.append(self._chunkPackets.copy())
                    case ReliableSessionElementKey.CHUNKS:
                        r.append(self._chunks)
                    case ReliableSessionElementKey.NOW_CHUNK:
                        r.append(self._nowChunk)
                    case _:
                        r.append(None)
        return r

    def setPacket(self, seq:int, data:bytes) -> None:
        with self._lock:
            self._chunkPackets[seq] = data