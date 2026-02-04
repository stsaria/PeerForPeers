from typing import Generator
from threading import Lock, Thread

from src.model.EncryptCollection import PrivateEncryptCollection
from src.model.NodeIdentify import NodeIdentify
from src.manager.WaitingResponses import WaitingResponses
from manager.AddrToEd25519PubKeys import AddrToEd25519PubKeys
from src.model.WaitingResponse import WAITING_RESPONSE_KEY, WaitingResponse
from src.core.ExtendedNet import ExtendedNet
from src.util.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from src.util.bytesCoverter import itob, btoi
from src.util import bytesSplitter, ed25519, encrypter
from src.protocol.Protocol import *
from src.protocol.ProgramProtocol import *

import os

class PrivateSecureNet(ExtendedNet):
    def init(self, myEd25519PrivateKey:Ed25519PrivateKey, sharedEd25519PrivateKey:Ed25519PrivateKey, sharedSecret:bytes):
        self._myEd25519PivKey:Ed25519PrivateKey = myEd25519PrivateKey
        self._sharedEd25519PivKey:Ed25519PrivateKey = sharedEd25519PrivateKey
        self._sharedSecret:bytes = sharedSecret

        self._encryptCollections:dict[tuple[str, int], PrivateEncryptCollection] = {}
        self._encryptCollectionsLock:Lock = Lock()

        self._sendCounts:dict[NodeIdentify, int] = {}
        self._sendCountsLock:Lock = Lock()

        self._recvCounts:dict[tuple[str, int], int] = {}

        self._ed25519PubKeys:dict[tuple[str, int], Ed25519PublicKey] = {}

    def hello(self, nodeIdentify:NodeIdentify) -> bool:
        waitingResponse = WaitingResponse(
            nodeIdentify=nodeIdentify,
            waitingInst=self,
            waitingType=PacketModeFlag.RESP_HELLO,
            otherInfo=sid
        )
        WaitingResponses.addKey(waitingResponse)
        pubKeyRaw = self._myEd25519PivKey.public_key().public_bytes_raw()
        self.sendTo(
            (
                itob(PacketFlag.PRIVATE_SECURE, SecurePacketElementSize.PACKET_FLAG)
                +itob(PacketModeFlag.HELLO, SecurePacketElementSize.MODE_FLAG)
                +(sid := os.urandom(ANY_SESSION_ID_SIZE))
                +pubKeyRaw
            ),
            nodeIdentify
        )
        if r := WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC) == None:
            WaitingResponses.delete(waitingResponse)
            return False
        WaitingResponses.delete(waitingResponse)
        e = PrivateEncryptCollection(
            sharedSecret=self._sharedSecret,
            salt=r[1]
        )
        nextSessionId = r[0]
        self.sendTo(
            (
                itob(PacketFlag.SECURE, SecurePacketElementSize.PACKET_FLAG)
                +itob(PacketModeFlag.SECOND_HELLO, SecurePacketElementSize.MODE_FLAG)
                +ed25519.sign(nextSessionId, self._myEd25519PivKey)
                +ed25519.sign(nextSessionId, self._sharedEd25519PivKey)
            ),
            nodeIdentify
        )
        if not AddrToEd25519PubKeys.put((nodeIdentify.ip, nodeIdentify.port), nodeIdentify.ed25519PublicKey):
            return False
        e.deriveAesKey(AesKeyInfoBase.PRIVATE_SECURE.format(pubKeyRaw).encode(STR_ENCODING))
        with self._encryptCollectionsLock:
            self._encryptCollections[nodeIdentify.ip, nodeIdentify.port] = e
        return True

    def sendToSecure(self, data:bytes, nodeIdentify:NodeIdentify) -> None:
        allSize = encrypter.calcAllSize((
            SOCKET_BUFFER
            -PrivateSecurePacketElementSize.MAGIC
            -PrivateSecurePacketElementSize.PACKET_FLAG
            -PrivateSecurePacketElementSize.MODE_FLAG
            -PrivateSecurePacketElementSize.SEQ
        ))
        l = len(data)
        if allSize < l: raise ValueError(f"Data too long {l}/{allSize}")
        with self._sendCountsLock and self._:
            self._sendCounts[nodeIdentify] = self._sendCounts.get(nodeIdentify, 0)+1
            seqB = itob(self._sendCounts, AES_NONCE_SIZE, ENDIAN)
            encrypted = encrypter.encryptAes(
                self._encryptCollections[nodeIdentify.ip, nodeIdentify.port].aesKey,
                data,
                itob(0, AES_NONCE_SIZE-SecurePacketElementSize.SEQ, ENDIAN)+seqB
            )
            self.sendTo(seqB+encrypted, nodeIdentify)
    
    def _recvHello(self, mD:bytes, addr:tuple[str, int]) -> None:
        sid, ed25519PubKeyB = bytesSplitter.split(
            mD,
            ANY_SESSION_ID_SIZE,
            SecurePacketElementSize.ED25519_PUBLIC_KEY
        )
        nextSid = os.urandom(ANY_SESSION_ID_SIZE)
        waitingResponse = WaitingResponse(
            nodeIdentify=NodeIdentify(
                ip=addr[0],
                port=addr[1],
                ed25519PublicKey=ed25519.getPubKeyByPubKeyBytes(ed25519PubKeyB)
            ),
            waitingInst=self,
            waitingType=PacketModeFlag.SECOND_HELLO,
            otherInfo=nextSid
        )
        WaitingResponses.addKey(waitingResponse)
        encryptCollection = PrivateEncryptCollection(
            sharedSecret=self._sharedSecret,
            salt=os.urandom(PrivateSecurePacketElementSize.AES_SALT)
        )
        signEndPart = (
            nextSid
            +encryptCollection.salt
        )
        self.sendTo(
            (
                itob(PacketFlag.PRIVATE_SECURE, PrivateSecurePacketElementSize.PACKET_FLAG)
                +itob(PacketModeFlag.RESP_HELLO, PrivateSecurePacketElementSize.MODE_FLAG)
                +signEndPart
                +ed25519.sign(sid+signEndPart, self._myEd25519PivKey)
                +ed25519.sign(sid+signEndPart, self._sharedEd25519PivKey)
            )
        )
        if WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC) == None:
            WaitingResponses.delete(waitingResponse)
            return
        WaitingResponses.delete(waitingResponse)
        if not AddrToEd25519PubKeys.put(addr, ed25519.getPubKeyByPubKeyBytes(ed25519PubKeyB)):
            return
        encryptCollection.deriveAesKey(AesKeyInfoBase.PRIVATE_SECURE.format(ed25519PubKeyB).encode(STR_ENCODING))
        with self._encryptCollectionsLock:
            self._encryptCollections[*addr] = encryptCollection
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
        nextSid, salt, signedByOtherPartyPivKey, signedBySharedPivKey = bytesSplitter.split(
            mD,
            ANY_SESSION_ID_SIZE,
            PrivateSecurePacketElementSize.AES_SALT,
            SecurePacketElementSize.ED25519_SIGN,
            SecurePacketElementSize.ED25519_SIGN
        )
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], PacketModeFlag.RESP_HELLO)
        if not WaitingResponses.containsKey(key):
            return
        wR:WaitingResponse = WaitingResponses.get(key)
        signData = (
            wR.otherInfo
            +nextSid
            +salt
        )
        if not ed25519.verify(signedByOtherPartyPivKey, signData, wR.nodeIdentify.ed25519PublicKey):
            return
        elif not ed25519.verify(signedBySharedPivKey, signData, self._sharedEd25519PivKey.public_key()):
            return
        WaitingResponses.updateValue(key, (nextSid, salt))
    def _recvSecondHello(self, mD:bytes, addr:tuple[str, int]) -> None:
        signedByOtherPartyPivKey, signedBySharedPivKey = bytesSplitter.split(
            mD,
            SecurePacketElementSize.ED25519_SIGN,
            SecurePacketElementSize.ED25519_SIGN
        )
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], PacketModeFlag.SECOND_HELLO)
        if not WaitingResponses.containsKey(key):
            return
        wR:WaitingResponse = WaitingResponses.get(key)
        signData = wR.otherInfo
        if not ed25519.verify(signedByOtherPartyPivKey, signData, wR.nodeIdentify.ed25519PublicKey):
            return
        elif not ed25519.verify(signedBySharedPivKey, signData, self._sharedEd25519PivKey.public_key()):
            return
        WaitingResponses.updateValue(key, 1)
    def recv(self) -> Generator[tuple[bytes, tuple[str, int]], None, None]:
        for data, addr in super().recv():
            if len(data) < PrivateSecurePacketElementSize.PACKET_FLAG+PrivateSecurePacketElementSize.MODE_FLAG:
                continue
            pFlag, mFlag, mainData = bytesSplitter.split(
                data+b"\x00",
                PrivateSecurePacketElementSize.PACKET_FLAG,
                PrivateSecurePacketElementSize.MODE_FLAG,
                includeRest=True
            )
            mainData = mainData[:len(mainData)-1]
            if btoi(pFlag, ENDIAN) != PacketFlag.PRIVATE_SECURE.value:
                continue

            try:
                mFlag = PacketModeFlag(btoi(mFlag, ENDIAN))
            except ValueError:
                continue

            match mFlag:
                case PacketModeFlag.HELLO:
                    target, args = self._recvHello, (mainData, addr)
                case PacketModeFlag.MAIN_DATA:
                    if (d := self._recvMainDataSynchronized(mainData, addr)) != None:
                        yield d, addr
                    continue
                case _:
                    continue
            
            Thread(
                target=target, args=args, daemon=True
            ).start()
