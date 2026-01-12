from typing import Generator
from threading import Lock, Thread

from manager.IpAndPortToEd25519PubKeys import IpToEd25519PubKeys
from src.model.EncryptCollection import EncryptCollection
from src.model.NodeIdentify import NodeIdentify
from src.manager.WaitingResponses import WaitingResponses
from src.model.WaitingResponse import WaitingResponse, WAITING_RESPONSE_KEY
from src.core.ExtendedNet import ExtendedNet
from src.util.ed25519 import Ed25519PrivateKey
from src.util.bytesCoverter import itob, btoi
from src.util import bytesSplitter, ed25519, encrypter
from src.protocol.Protocol import *
from src.protocol.ProgramProtocol import *

import os

class SecureNet(ExtendedNet):
    def init(self, myEd25519PrivateKey:Ed25519PrivateKey):
        self._ed25519PivKey:Ed25519PrivateKey = myEd25519PrivateKey

        self._encryptCollections:dict[tuple[str, int], EncryptCollection] = {}
        self._encryptCollectionsLock:Lock = Lock()

        self._sendCounts:dict[NodeIdentify, int] = {}
        self._sendCountsLock:Lock = Lock()

        self._recvCounts:dict[tuple[str, int], int] = {}
    def hello(self, nodeIdentify:NodeIdentify) -> bool:
        waitingResponse = WaitingResponse(
            nodeIdentify=nodeIdentify,
            waitingInst=self,
            waitingType=PacketModeFlag.RESP_HELLO,
            otherInfo=sid
        )
        WaitingResponses.addKey(waitingResponse)
        self.sendTo(
            (
                itob(PacketFlag.SECURE, SecurePacketElementSize.PACKET_FLAG)
                +itob(PacketModeFlag.HELLO, SecurePacketElementSize.MODE_FLAG)
                +(sid := os.urandom(ANY_SESSION_ID_SIZE))
                +self._ed25519PivKey.public_key().public_bytes_raw()
            ),
            nodeIdentify
        )
        if r := WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC) == None:
            WaitingResponses.delete(waitingResponse)
            return False
        WaitingResponses.delete(waitingResponse)
        if not IpToEd25519PubKeys.put((nodeIdentify.ip, nodeIdentify.port), nodeIdentify.ed25519PublicKey):
            return False
        e = EncryptCollection(
            salt=r[2],
            myX25519PivKey=encrypter.generateX25519PivKey(),
            otherPartyX25519PubKey=encrypter.getX25519PubKeyByPubKeyBytes(r[1])
        )
        nextSessionId = r[0]
        pubKeyRaw = e.myX25519PivKey.public_key().public_bytes_raw()
        self.sendTo(
            (
                itob(PacketFlag.SECURE, SecurePacketElementSize.PACKET_FLAG)
                +itob(PacketModeFlag.SECOND_HELLO, SecurePacketElementSize.MODE_FLAG)
                +pubKeyRaw
                +ed25519.sign(nextSessionId+pubKeyRaw, self._ed25519PivKey)
            ),
            nodeIdentify
        )
        e.deriveSharedSecretByX25519(X25519DeriveInfoBase.SECURE)
        e.deriveAesKey(X25519AndAesKeyInfoBase.SECURE)
        with self._encryptCollectionsLock:
            self._encryptCollections[nodeIdentify.ip, nodeIdentify.port] = e
        return True
    
    def sendToSecure(self, data:bytes, nodeIdentify:NodeIdentify) -> int:
        allSize = encrypter.calcAllSize((
            SOCKET_BUFFER
            -SecurePacketElementSize.MAGIC
            -SecurePacketElementSize.PACKET_FLAG
            -SecurePacketElementSize.MODE_FLAG
            -SecurePacketElementSize.SEQ
        ))
        l = len(data)
        if allSize < l: raise ValueError(f"Data too long {l}/{allSize}")
        with self._sendCountsLock and self._encryptCollectionsLock:
            self._sendCounts[nodeIdentify] = self._sendCounts.get(nodeIdentify, 0)+1
            seqB = itob(self._sendCounts, AES_NONCE_SIZE, ENDIAN)
            encrypted = encrypter.encryptAes(
                self._encryptCollections[nodeIdentify.ip, nodeIdentify.port].aesKey,
                data,
                itob(0, AES_NONCE_SIZE-SecurePacketElementSize.SEQ, ENDIAN)+seqB
            )
            return self.sendTo(seqB+encrypted, nodeIdentify)


    

    
    def _recvHello(self, mD:bytes, addr:tuple[str, int]) -> None:
        sid, ed25519PubKeyB = bytesSplitter.split(
            mD,
            ANY_SESSION_ID_SIZE,
            SecurePacketElementSize.ED25519_PUBLIC_KEY
        )
        nextSid = os.urandom(ANY_SESSION_ID_SIZE)
        e = EncryptCollection(
            salt=os.urandom(SecurePacketElementSize.AES_SALT),
            myX25519PivKey=encrypter.generateX25519PivKey()
        )
        signEndPart = (
            nextSid
            +e.myX25519PivKey.public_key().public_bytes_raw()
            +e.salt
        )
        waitingResponse = WaitingResponse(
            nodeIdentify=NodeIdentify(
                addr[0],
                addr[1],
                ed25519.getPubKeyByPubKeyBytes(ed25519PubKeyB)
            ),
            waitingInst=self,
            waitingType=PacketModeFlag.SECOND_HELLO,
            otherInfo=nextSid
        )
        WaitingResponses.addKey(waitingResponse)
        self.sendTo(
            (
                itob(PacketFlag.SECURE, SecurePacketElementSize.PACKET_FLAG)
                +itob(PacketModeFlag.RESP_HELLO, SecurePacketElementSize.MODE_FLAG)
                +signEndPart
                +ed25519.sign(sid+signEndPart, self._ed25519PivKey)
            )
        )
        if r := WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC) == None:
            WaitingResponses.delete(waitingResponse)
            return
        WaitingResponses.delete(waitingResponse)
        if not IpToEd25519PubKeys.put(addr, waitingResponse.nodeIdentify.ed25519PublicKey):
            return
        e.otherPartyX25519PubKey = encrypter.getX25519PubKeyByPubKeyBytes(r)
        e.deriveSharedSecretByX25519(X25519DeriveInfoBase.SECURE)
        e.deriveAesKey(X25519AndAesKeyInfoBase.SECURE)
        with self._encryptCollectionsLock:
            self._encryptCollections[*addr] = e
    def _recvMainDataSynchronized(self, mD:bytes, addr:tuple[str, int]) -> bytes:
        with self._encryptCollectionsLock:
            if (encryptCollection := self._encryptCollections.get(addr)) == None:
                return
        if encryptCollection.aesKey == None:
            return
        seqB, mainEncryptedData = bytesSplitter.split(
            mD,
            SecurePacketElementSize.SEQ
        )
        if self._recvCounts.get(addr) >= btoi(seqB, ENDIAN):
            return
        mainDecryptedData = encrypter.decryptAes(
            encryptCollection.aesKey,
            mainEncryptedData,
            itob(0, AES_NONCE_SIZE-SecurePacketElementSize.SEQ, ENDIAN)+seqB,
            None
        )
        if mainDecryptedData != None:
            self._recvCounts[addr] = self._recvCounts.get(addr, 0)+1
        return mainDecryptedData
        






    def _recvRespHello(self, mD:bytes, addr:tuple[str, int]) -> None:
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, PacketModeFlag.RESP_HELLO, None)
        if not WaitingResponses.containsKey(key):
            return
        nextSessionIdB, x25519PubKeyB, aesSaltB, signedB = bytesSplitter.split(
            mD,
            ANY_SESSION_ID_SIZE,
            SecurePacketElementSize.X25519_PUBLIC_KEY,
            SecurePacketElementSize.AES_SALT,
            SecurePacketElementSize.ED25519_SIGN
        )

        wR = WaitingResponses.getWaitingResponseObjByKey(key)
        if not ed25519.verify(wR.otherInfo+nextSessionIdB+x25519PubKeyB+aesSaltB, signedB, wR.nodeIdentify.ed25519PublicKey):
            return
        WaitingResponses.updateValue(key, (nextSessionIdB, x25519PubKeyB, aesSaltB))
    def _recvSecondHello(self, mD:bytes, addr:tuple[str, int]) -> None:
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, PacketModeFlag.SECOND_HELLO, None)
        if not WaitingResponses.containsKey(key):
            return
        x25519PubKeyB, signedB = bytesSplitter.split(
            mD,
            SecurePacketElementSize.X25519_PUBLIC_KEY,
            SecurePacketElementSize.ED25519_SIGN
        )
        wR = WaitingResponses.getWaitingResponseObjByKey(key)
        if not ed25519.verify(wR.otherInfo+x25519PubKeyB, signedB, wR.nodeIdentify.ed25519PublicKey):
            return
        WaitingResponses.updateValue(key, x25519PubKeyB)
    def recv(self) -> Generator[tuple[bytes, tuple[str, int]], None, None]:
        for data, addr in super().recv():
            pFlag, mFlag, mainData = bytesSplitter.split(
                data,
                SecurePacketElementSize.PACKET_FLAG,
                SecurePacketElementSize.MODE_FLAG,
                includeRest=True
            )
            if pFlag != PacketFlag.SECURE.value:
                continue
            try:
                mFlag = PacketModeFlag(mFlag)
            except ValueError:
                continue

            match mFlag:
                case PacketModeFlag.HELLO:
                    target, args = self._recvHello, (mainData, addr)
                case PacketModeFlag.MAIN_DATA:
                    if (d := self._recvMainDataSynchronized(mainData, addr)) != None:
                        yield d, addr
                    continue
                case PacketModeFlag.RESP_HELLO:
                    target, args = self._recvRespHello, (mainData, addr)     
                case PacketModeFlag.SECOND_HELLO:
                    target, args = self._recvSecondHello, (mainData, addr)    
                case PacketModeFlag.PONG:
                    target, args = self._recvPong, (mainData[ANY_SESSION_ID_SIZE:], addr)
                case _:
                    continue

            Thread(
                target=target, args=args, daemon=True
            ).start()

