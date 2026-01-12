import math
import os
from typing import Callable, Generator
from threading import Event, Lock, Thread

from src.manager.WaitingResponses import WaitingResponses
from src.model.NodeIdentify import NodeIdentify
from src.model.WaitingResponse import WAITING_RESPONSE_KEY, WaitingResponse
from src.core.ExtendedNet import ExtendedNet
from src.model.EncryptCollection import EncryptCollection
from src.model.ReleableSession import ReliableSession, ReliableSessionElementKey
from src.util import bytesSplitter, encrypter
from src.util.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from src.protocol.Protocol import *
from src.protocol.ProgramProtocol import *
from src.util import ed25519
from src.util.bytesCoverter import btoi, itob

class ReliableRecvFailed(Exception):
    pass

class ReliableNet:
    def __init__(self, netObj:ExtendedNet, ed25519PrivateKey:Ed25519PrivateKey):
        self._net = netObj
        self._ed25519PrivateKey = ed25519PrivateKey
        self._sessions:dict[bytes, ReliableSession] = {}
        self._sessionsLock:Lock = Lock()
    def _sendChunk(self, nodeIdentify:NodeIdentify, sid:bytes, sendData:list[bytes], startSeq:int, encryptCollection:EncryptCollection, redundancyCond:Callable[[], bool] = lambda redundancyCount: True) -> bool:
        if len(sendData) > RELIABLE_PACKETS_PER_CHUNK:
            raise ValueError("Size of packets per chunk is too big")
        sentData = {}
        for i, d in enumerate(sendData):
            seq = startSeq+i
            sendData[seq] = sD = (
                itob(PacketFlag.RELIABLE, ReliablePacketElementSize.PACKET_FLAG)
                +itob(PacketModeFlag.MAIN_DATA)
                +sid
                +(seqB := itob(seq, ReliablePacketElementSize.SEQ_AND_CHUNK_COUNT))
            )+encrypter.encryptAes(
                encryptCollection.aesKey,
                d,
                itob(0, AES_NONCE_SIZE-SecurePacketElementSize.SEQ, ENDIAN)+seqB,
                None
            )
            self._net.sendTo(sD, nodeIdentify)
        c = 0
        badDataSeq = []
        while redundancyCond(c):
            checkSid = os.urandom(ANY_SESSION_ID_SIZE)
            waitingResponse = WaitingResponse(
                nodeIdentify,
                self,
                waitingType=PacketModeFlag.CHUNK_CHECK,
                otherInfoInKey=sid,
                otherInfo=checkSid
            )
            if (r := WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC)) == None:
                WaitingResponses.delete(waitingResponse)
                continue
            WaitingResponses.delete(waitingResponse)
            if len(r) == 0:
                break
            if c == 0:
                [badDataSeq.append(s) for s in r]
            for s in r:
                if not s in badDataSeq:
                    continue
                elif len(sendData)+startSeq-1 < s:
                    continue
                self._net.sendTo(sentData[s], nodeIdentify)
        return True


    def send(self, nodeIdentify:NodeIdentify, sid:bytes, sendDataGenerator:Generator[bytes, None, None], size:int) -> bool:
        waitingResponse = WaitingResponse(
            nodeIdentify=nodeIdentify,
            waitingInst=self,
            waitingType=PacketModeFlag.RESP_HELLO,
            otherInfoInKey=sid
        )   
        WaitingResponses.addKey(waitingResponse)
        e = EncryptCollection(
            myX25519PivKey=encrypter.generateX25519PivKey()
        )
        self._net.sendTo(
            (
                itob(PacketFlag.RELIABLE, SecurePacketElementSize.PACKET_FLAG)
                +itob(PacketModeFlag.HELLO, SecurePacketElementSize.MODE_FLAG)
                +(pk := e.myX25519PivKey.public_key().public_bytes_raw())
                +ed25519.sign(pk, self._ed25519PrivateKey)
            ),
            nodeIdentify
        )
        if (r := WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC)) == None:
            WaitingResponses.delete(waitingResponse)
            return False
        WaitingResponses.delete(waitingResponse)
        e.otherPartyX25519PubKey = r
        e.deriveSharedSecretByX25519(X25519DeriveInfoBase.RELIABLE)
        e.deriveAesKey(X25519AndAesKeyInfoBase.RELIABLE)

        chunk = []
        cache = b""
        seq = 0

        mainDataSizePerPacket = (
            SOCKET_BUFFER
            -ReliablePacketElementSize.MAGIC
            -ReliablePacketElementSize.PACKET_FLAG
            -ReliablePacketElementSize.MODE_FLAG
            -ReliablePacketElementSize.SEQ_AND_CHUNK_COUNT
            -ReliablePacketElementSize.REDUNDANCY_COUNT
        )

        for d in sendDataGenerator:
            if (l := len(d)) > size:
                raise ValueError(f"Bytes is too big {l}/{size}")
            cache += d
            while len(cache) >= mainDataSizePerPacket:
                content = cache[0:mainDataSizePerPacket]
                chunk.append(content)
                seq += 1
                cache = cache[len(content):]
                if len(chunkBs) >= RELIABLE_PACKETS_PER_CHUNK:
                    if not self._sendChunk(nodeIdentify, chunk, seq//RELIABLE_PACKETS_PER_CHUNK, e):
                        return False
                    chunkBs = []

        
    def _timer(self, timeoutMilliSec:int, stop:Event, onTimeout:function) -> None:
        if not stop.wait(timeoutMilliSec*1000):
            onTimeout()
    def recvFor(self, id:bytes, size:int, otherPartyEd25519PublicKey:Ed25519PublicKey) -> Generator[bytes, None, None]:
        recvGen = yield
        with self._sessionsLock:
            s = ReliableSession(
                sessionId=id,
                recvGenerator=recvGen,
                size=size,
                otherPartyEd25519PublicKey=otherPartyEd25519PublicKey
            )
            s.calcChunks() = ReliableSession
            self._sessions[id] = s
        return recvGen
    def _recvHello(self, session:ReliableSession, mD:bytes, addr:tuple[str, int]) -> None:
        x25519PubKeyB, signedB = bytesSplitter.split(
            mD,
            ReliablePacketElementSize.X25519_PUBLIC_KEY,
            ReliablePacketElementSize.ED25519_SIGN
        )
        if not ed25519.verify(x25519PubKeyB, signedB, session.otherPartyEd25519PublicKey):
            return
        e = EncryptCollection(
            salt=os.urandom(SecurePacketElementSize.AES_SALT),
            myX25519PivKey=encrypter.generateX25519PivKey(),
            otherPartyX25519PubKey=encrypter.getX25519PubKeyByPubKeyBytes(x25519PubKeyB)
        )
        signData = (
            e.myX25519PivKey.public_key().public_bytes_raw(),
            e.salt
        )
        self._net.sendTo(
            (
                itob(PacketFlag.RELIABLE, SecurePacketElementSize.PACKET_FLAG)
                +itob(PacketModeFlag.RESP_HELLO, SecurePacketElementSize.MODE_FLAG)
                +signData
                +ed25519.sign(signData, self._ed25519PrivateKey)
            )
        )
        e.deriveSharedSecretByX25519(X25519DeriveInfoBase.RELIABLE)
        e.deriveAesKey(X25519AndAesKeyInfoBase.RELIABLE)
        with self._sessionsLock:
            self._sessions[addr]._encryptCollection = e
    def _recvRespHello(self, session:ReliableSession, mD:bytes, addr:tuple[str, int]) -> None:
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, PacketModeFlag.RESP_HELLO, session.sessionId)
        if not WaitingResponses.containsKey(key):
            return
        x25519PubKeyB, aesSaltB, signedB = bytesSplitter.split(
            mD,
            ReliablePacketElementSize.X25519_PUBLIC_KEY,
            ReliablePacketElementSize.AES_SALT,
            ReliablePacketElementSize.ED25519_SIGN
        )
        wR = WaitingResponses.getWaitingResponseObjByKey(key)
        if not ed25519.verify(x25519PubKeyB, signedB, wR.nodeIdentify.ed25519PublicKey):
            return
        WaitingResponses.updateValue(key, (x25519PubKeyB, aesSaltB))
    def _finishRecv(self, session:ReliableSession, sendRest:bool = True) -> None:
        if sendRest:
            packets:dict[int, bytes] = session.get(ReliableSessionElementKey.CHUNK_PACKETS)
            for seq in sorted(list(packets.keys()), key=lambda seqAndContent: seqAndContent[0]):
                session.sendGen(packets.get(seq))
        with self._sessionsLock:
            self._sessions.pop(session.sessionId, None)
        session.closeGen()
    def _getChunkMissingPacketSeqs(self, session:ReliableSession) -> list[int]:
        seqs = []
        mainDataSizePerPacket = (
            SOCKET_BUFFER
            -ReliablePacketElementSize.MAGIC
            -ReliablePacketElementSize.PACKET_FLAG
            -ReliablePacketElementSize.MODE_FLAG
            -ReliablePacketElementSize.SEQ_AND_CHUNK_COUNT
            -ReliablePacketElementSize.REDUNDANCY_COUNT
        )
        nowChunk, chunks, chunkPackets = session.get(
            ReliableSessionElementKey.NOW_CHUNK,
            ReliableSessionElementKey.CHUNKS,
            ReliableSessionElementKey.CHUNK_PACKETS
        )
        chunkPackets:dict[int, bytes] = chunkPackets
        if nowChunk == chunks:
            stop = session.size - mainDataSizePerPacket*(nowChunk-1)*RELIABLE_PACKETS_PER_CHUNK
        else:
            stop = mainDataSizePerPacket*nowChunk*RELIABLE_PACKETS_PER_CHUNK
        for i in range((nowChunk-1)*RELIABLE_PACKETS_PER_CHUNK+1, stop):
            if not chunkPackets.get(i):
                seqs.append(i)
        return seqs
    def _recvMainData(self, session:ReliableSession, mD:bytes) -> None:
        seqB, mainData = bytesSplitter.split(
            mD,
            ReliablePacketElementSize.SEQ_AND_CHUNK_COUNT,
            includeRest=True
        )
        seq = btoi(seqB, ENDIAN)
        elements = session.get(
            ReliableSessionElementKey.NOW_CHUNK,
            ReliableSessionElementKey.CHUNK_PACKETS,
            ReliableSessionElementKey.ENCRYPT_COLLECTION
        )

        nowChunk:int = elements[0]
        chunkPackets:dict[int, bytes] = elements[1]
        encryptCollection:EncryptCollection = elements[2]
        if nowChunk*RELIABLE_PACKETS_PER_CHUNK < seq:
            return
        elif chunkPackets.get(seq):
            return
        elif (decrypted := encrypter.decryptAes(
            encryptCollection.aesKey,
            mainData,
            itob(0, AES_NONCE_SIZE-SecurePacketElementSize.SEQ, ENDIAN)+seqB,
            None
        )) == None:
            return
        session.setPacket(seq, decrypted)
        
        if nowChunk-1*RELIABLE_PACKETS_PER_CHUNK+seq == math.ceil(
            session.size/(
                SOCKET_BUFFER
                -ReliablePacketElementSize.MAGIC
                -ReliablePacketElementSize.PACKET_FLAG
                -ReliablePacketElementSize.MODE_FLAG
                -ReliablePacketElementSize.SEQ_AND_CHUNK_COUNT
                -ReliablePacketElementSize.REDUNDANCY_COUNT
            )
        ):
            self._finishRecv(session)
    def _recvChunkCheck(self, session:ReliableSession, mD:bytes, addr:tuple[str, int]) -> None:
        signed = bytesSplitter.split(
            mD,
            ReliablePacketElementSize.ED25519_SIGN
        )
        if not ed25519.verify(itob(session.get(ReliableSessionElementKey.NOW_CHUNK), ReliablePacketElementSize.SEQ_AND_CHUNK_COUNT, ENDIAN), signed, session.otherPartyEd25519PublicKey):
            return
        missingSeqs = self._getChunkMissingPacketSeqs(session)
        missingSeqsB = b"".join([itob(s, ReliablePacketElementSize.SEQ_AND_CHUNK_COUNT, ENDIAN) for s in missingSeqs])
        self._net.sendTo(
            (
                +itob(PacketFlag.RELIABLE, ReliablePacketElementSize.PACKET_FLAG)
                +itob(PacketModeFlag.RESP_CHUNK_CHECK)
                +session.sessionId
                +missingSeqsB
                +ed25519.sign(missingSeqsB, self._ed25519PrivateKey)
            ),
            addr
        )
    def _recvRespChunkCheck(self, session:ReliableSession, mD:bytes, addr:tuple[str, int]) -> None:
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, PacketModeFlag.RESP_CHUNK_CHECK, session.sessionId)
        if not WaitingResponses.containsKey(key):
            return
        signed, badPacketSeqsB = bytesSplitter.split(
            mD,
            ReliablePacketElementSize.ED25519_SIGN,
            includeRest=True
        )
        if len(badPacketSeqsB) % ReliablePacketElementSize.SEQ_AND_CHUNK_COUNT:
            return
        wR = WaitingResponses.getWaitingResponseObjByKey(key)
        if not ed25519.verify(wR.otherInfo+badPacketSeqsB, signed, wR.nodeIdentify.ed25519PublicKey):
            return
        badPacketSeqs = [
            btoi(
                badPacketSeqsB[
                    (i)*ReliablePacketElementSize.SEQ_AND_CHUNK_COUNT
                    :(i+1)*ReliablePacketElementSize.SEQ_AND_CHUNK_COUNT
                ],
                ENDIAN
            ) for i in range(
                len(badPacketSeqs) / ReliablePacketElementSize.SEQ_AND_CHUNK_COUNT
            )
        ]
        WaitingResponses.updateValue(key, badPacketSeqs)




    def finishSession(self, sessionId:bytes) -> None:
        with self._sessionsLock:
            if (session := self._sessions.get(sessionId)):
                self._finishRecv(session)




    def recver(self) -> None:
        for data, addr in self._net.recv():
            pFlag, mFlag, sid, mainData = bytesSplitter.split(
                data,
                ReliablePacketElementSize.PACKET_FLAG,
                ReliablePacketElementSize.MODE_FLAG,
                ReliablePacketElementSize.SESSION_ID,
                includeRest=True
            )
            if pFlag != PacketFlag.RELIABLE.value:
                continue
            try:
                mFlag = PacketModeFlag(mFlag)
            except ValueError:
                continue
            with self._sessionsLock:
                if (session := self._sessions.get(sid)) == None:
                    continue
            match mFlag:
                case PacketModeFlag.HELLO:
                    target, args = self._recvHello, (session, mainData, addr)
                case PacketModeFlag.RESP_HELLO:
                    target, args = self._recvRespHello, (session, mainData, addr)
                case PacketModeFlag.MAIN_DATA:
                    target, args = self._recvMainData, (session, mainData)
                case PacketModeFlag.CHUNK_CHECK:
                    target, args = self._recvChunkCheck, (session, mainData)
                case PacketModeFlag.RESP_CHUNK_CHECK:
                    target, args = self._recvRespChunkCheck, (session, mainData, addr)
                case _:
                    continue
            Thread(
                target=target, args=args, daemon=True
            ).start()
                
                




                


