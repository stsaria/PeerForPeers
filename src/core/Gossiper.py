import random
from time import sleep, time
import xxhash
from threading import Lock, Thread, Event

from src.core.ExtendedNet import ExtendedNet
from src.model.NodeIdentify import NodeIdentify
from src.util import bytesSplitter, ed25519
from src.util.bytesCoverter import *
from src.protocol.Protocol import *
from src.protocol.ProgramProtocol import *
from src.util.ed25519 import Ed25519PrivateKey

class Gossiper:
    def __init__(self, extendedNet:ExtendedNet, ed25519PrivateKey:Ed25519PrivateKey) -> None:
        self._extendedNet:ExtendedNet = extendedNet
        self._ed25519PrivateKey:Ed25519PrivateKey = ed25519PrivateKey
        self._waitingPubKeys:dict[bytes, tuple[Event, bytes]] = {}
        self._nodes: list[bytes] = []
        self._nodeFoundTimes: list[int] = []
        self._nodesLock:Lock = Lock()
    def addNode(self, nodeIdentify:NodeIdentify) -> None:
        nodeBytes = (
            stob(nodeIdentify.ip, GossipPacketElementSize.IP, STR_ENCODING)
            +itob(nodeIdentify.port, GossipPacketElementSize.PORT, ENDIAN),
            +nodeIdentify.ed25519PublicKey.public_bytes_raw()
        )
        with self._nodesLock:
            self._nodes.append(nodeBytes)
    def _pingAndAddNode(self, nodeBytes:bytes, nodeIdentify:NodeIdentify) -> None:
        if self._extendedNet.ping(nodeIdentify) == None:
            return
        with self._nodesLock:
            if nodeBytes in self._nodes:
                return
            self._nodes.append(nodeBytes)
            self._nodeFoundTimes.append(time())
    def waitAndGetNodeByPublicKey(self, publicKey:bytes, timeoutSec:int | None) -> NodeIdentify | None:
        event = Event()
        with self._nodesLock:
            self._waitingPubKeys[publicKey] = (event, None)
        if not event.wait(timeoutSec):
            return None
        with self._nodesLock:
            nIB = self._waitingPubKeys[publicKey][1]
        ipB, portB, publicKeyB = bytesSplitter(
            nIB,
            GossipPacketElementSize.IP,
            GossipPacketElementSize.PORT,
            GossipPacketElementSize.ED25519_PUBLIC_KEY
        )
        return NodeIdentify(
            ip=btos(ipB, STR_ENCODING),
            port=btoi(portB, ENDIAN),
            ed25519PublicKey=ed25519.getPubKeyByPubKeyBytes(publicKeyB)
        )
    def _syncer(self) -> None:
        while True:
            with self._nodesLock:
                sendNodeB = random.sample(self._nodes)
                selectedNodes = random.sample(
                    self._nodes,
                    min(MAX_GOSSIP_NODES_FOR_SEND, len(self._nodes))
                )
            selectedNodes.remove(sendNodeB)

            ipB, portB, publicKeyB = bytesSplitter(
                sendNodeB,
                GossipPacketElementSize.IP,
                GossipPacketElementSize.PORT,
                GossipPacketElementSize.ED25519_PUBLIC_KEY
            )

            addr = (
                btos(ipB, STR_ENCODING),
                itob(portB, ENDIAN)
            )
        
            d = b"".join(selectedNodes)
            hashB = xxhash.xxh64(d).digest()

            self._extendedNet.sendTo(
                itob(PacketFlag.GOSSIP, GossipPacketElementSize.PACKET_FLAG)
                +itob(PacketModeFlag.GOSSIP, GossipPacketElementSize.MODE_FLAG)
                +hashB
                +d,
                addr
            )

            sleep(SyncIntervalSec.GOSSIP)
    def _recvGossip(self, mD:bytes, addr:tuple[str, int]) -> None:
        nodes = []

        hashB, mD = bytesSplitter.split(
            mD,
            GossipPacketElementSize.XXHASH64,
            includeRest=True
        )
        if xxhash.xxh64(mD).digest() != hashB:
            return
        
        senderEd25519PubKeyB, mD = bytesSplitter.split(
            mD,
            GossipPacketElementSize.ED25519_PUBLIC_KEY,
            includeRest=True
        )
        
        while len(mD) >= (
            GossipPacketElementSize.IP
            +GossipPacketElementSize.PORT
            +GossipPacketElementSize.ED25519_PUBLIC_KEY
        ):
            ipBytes, portBytes, publicKeyBytes, mD = bytesSplitter.split(
                mD,
                GossipPacketElementSize.IP,
                GossipPacketElementSize.PORT,
                GossipPacketElementSize.ED25519_PUBLIC_KEY,
                includeRest=True
            )
            nodes.append(
                (
                    ipBytes
                    +portBytes
                    +publicKeyBytes,
                    NodeIdentify(
                        ip=btos(ipBytes, STR_ENCODING),
                        port=itob(portBytes, ENDIAN),
                        ed25519PublicKey=ed25519.getPubKeyByPubKeyBytes(publicKeyBytes)
                    )
                )
            )
        nodes.append(
            (
                stob(addr[0], GossipPacketElementSize.IP, STR_ENCODING)
                +itob(addr[1], GossipPacketElementSize.PORT, ENDIAN)
                +senderEd25519PubKeyB,
                NodeIdentify(
                    ip=addr[0],
                    port=addr[1],
                    ed25519PublicKey=ed25519.getPubKeyByPubKeyBytes(senderEd25519PubKeyB)
                )
            )
        )
        for nB, nI in nodes:
            Thread(target=self._pingAndAddNode, args=(nB, nI)).start()
    def gc(self) -> None:
        with self._nodesLock:
            for i, n in enumerate(self._nodes): 
                if time() - self._nodeFoundTimes[i] <= TTL_GOSSIP_NODE:
                    break
                self._nodes.remove(n)
                self._nodeFoundTimes.remove(self._nodeFoundTimes[i])
    def _recv(self) -> None:
        for data, addr in self._extendedNet.recv():
            if len(data) < GossipPacketElementSize.PACKET_FLAG+GossipPacketElementSize.MODE_FLAG:
                continue
            pFlag, mFlag, mainData = bytesSplitter.split(
                data+b"\x00",
                GossipPacketElementSize.PACKET_FLAG,
                GossipPacketElementSize.MODE_FLAG,
                includeRest=True
            )
            mainData = mainData[:-1]
            if pFlag != itob(PacketFlag.GOSSIP, GossipPacketElementSize.PACKET_FLAG):
                continue
            try:
                mFlag = PacketModeFlag(itob(mFlag, SecurePacketElementSize.MODE_FLAG))
            except ValueError:
                continue
            if mFlag == PacketModeFlag.GOSSIP:
                target, args = self._recvGossip, (mainData, addr)
            Thread(target=target, args=args).start()
    def start(self) -> None:
        Thread(target=self._recv, daemon=True).start()
        Thread(target=self._syncer, daemon=True).start()