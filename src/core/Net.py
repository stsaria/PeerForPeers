from socket import (
    socket as Socket,
    AF_INET, AF_INET6,
    SOCK_DGRAM,
    SOL_SOCKET, SO_REUSEADDR,
)
from typing import Generator
import select

from src.manager.BannedIps import BannedIps
from src.protocol.Protocol import MAGIC, SOCKET_BUFFER, PacketElementSize
from src.model.NetConfig import NetConfig


class Net:
    def __init__(self, netConfig: NetConfig) -> None:
        self._netConfig = netConfig
        self._socks: list[Socket] = []

        sock4 = Socket(AF_INET, SOCK_DGRAM)
        sock4.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        sock4.bind(netConfig.addrV4)
        self._socks.append(sock4)

        sock6 = Socket(AF_INET6, SOCK_DGRAM)
        sock6.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        sock6.bind(netConfig.addrV6)
        self._socks.append(sock6)

    def sendTo(self, data:bytes, addr:tuple[str, int]) -> int:
        return self._socks[1 if ':' in addr[0] else 0].sendto(MAGIC + data, addr)
    def recv(self) -> Generator[tuple[bytes, tuple[str, int]], None, None]:
        while True:
            try:
                readable, _, _ = select.select(self._socks, [], [])
                for sock in readable:
                    sock:Socket = sock
                    data, addr = sock.recvfrom(SOCKET_BUFFER)

                    if not data.startswith(MAGIC):
                        continue
                    if BannedIps.contains(addr[0]):
                        continue

                    yield data[PacketElementSize.MAGIC:], addr
            except Exception:
                return

    def close(self) -> None:
        for sock in self._socks:
            sock.close()
