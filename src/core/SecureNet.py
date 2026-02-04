import random
from typing import Generator
from threading import Lock, Thread

from src.manager.AddrToEd25519PubKeys import AddrToEd25519PubKeys
from src.model.EncryptCollection import EncryptCollection
from src.model.NodeIdentify import NodeIdentify
from src.manager.WaitingResponses import WaitingResponses
from src.model.WaitingResponse import WaitingResponse, WAITING_RESPONSE_KEY
from src.core.ExtendedNet import ExtendedNet
from src.util.ed25519 import Ed25519PrivateKey
from src.util.bytesCoverter import *
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
    def agencyPing(self, nodeIdentifyToPing:NodeIdentify) -> bool:
        sid = os.urandom(ANY_SESSION_ID_SIZE)
        waitingResponse = WaitingResponse(
            nodeIdentify=nodeIdentifyToPing,
            waitingInst=self,
            waitingType=PacketModeFlag.MAIN_DATA,
            otherInfoInKey=sid
        )
        WaitingResponses.addKey(waitingResponse)
        with self._sendCountsLock:
            nodeIdentifyToAgency = random.choice(list(self._sendCounts.keys()))
        self.sendToSecure(
            itob(PacketFlag.SECURE, SecurePacketElementSize.PACKET_FLAG)
            +itob(PacketModeFlag.PING, SecurePacketElementSize.MODE_FLAG)
            +sid
            +stob(nodeIdentifyToPing.ip, SecurePacketElementSize.IP, STR_ENCODING)
            +itob(nodeIdentifyToPing.port, SecurePacketElementSize.PORT, ENDIAN),
            nodeIdentifyToAgency
        )
        if WaitingResponses.waitAndGet(waitingResponse, TIME_OUT_MILLI_SEC*2) == None:
            WaitingResponses.delete(waitingResponse)
            return False
        WaitingResponses.delete(waitingResponse)
        return True
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
        if not AddrToEd25519PubKeys.put((nodeIdentify.ip, nodeIdentify.port), nodeIdentify.ed25519PublicKey):
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
        with self._encryptCollectionsLock:
            if addr in self._encryptCollections.keys():
                return
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
        if not AddrToEd25519PubKeys.put(addr, waitingResponse.nodeIdentify.ed25519PublicKey):
            return
        e.otherPartyX25519PubKey = encrypter.getX25519PubKeyByPubKeyBytes(r)
        e.deriveSharedSecretByX25519(X25519DeriveInfoBase.SECURE)
        e.deriveAesKey(X25519AndAesKeyInfoBase.SECURE)
        if not self.agencyPing(waitingResponse.nodeIdentify):
            return
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
    def _recvAgencyPing(self, mD:bytes, addr:tuple[str, int]) -> None:
        if (ed25519PubKey := AddrToEd25519PubKeys.get(addr)) == None:
            return
        sid, ipB, portB = bytesSplitter.split(
            mD,
            ANY_SESSION_ID_SIZE,
            SecurePacketElementSize.IP,
            SecurePacketElementSize.PORT
        )
        status = False
        for _ in range(PING_WINDOW):
            if self.ping((btos(ipB, STR_ENCODING), btoi(portB, ENDIAN))) != None:
                status = True
                break
        self.sendToSecure(
            itob(PacketFlag.SECURE, SecurePacketElementSize.PACKET_FLAG)
            +itob(PacketModeFlag.RESP_AGENCY_PING, SecurePacketElementSize.MODE_FLAG)
            +(signData := (
                sid
                +bytes(status)
            ))
            +ed25519.sign(signData, self._ed25519PivKey),
            NodeIdentify(ip=addr[0], port=addr[1], ed25519PublicKey=ed25519PubKey)
        )
    def _recvRespAgencyPing(self, mD:bytes, addr:tuple[str, int]) -> None:
        sid, statusB, signedB = bytesSplitter.split(
            mD,
            ANY_SESSION_ID_SIZE,
            SecurePacketElementSize.IS_SUCCESS_AGENCY_PING,
            SecurePacketElementSize.ED25519_SIGN
        )
        key:WAITING_RESPONSE_KEY = (addr[0], addr[1], self, PacketModeFlag.RESP_AGENCY_PING, sid)
        if not WaitingResponses.containsKey(key):
            return
        wR = WaitingResponses.getWaitingResponseObjByKey(key)
        if not ed25519.verify(sid+statusB, signedB, wR.nodeIdentify.ed25519PublicKey):
            return
        WaitingResponses.updateValue(key, bool(btoi(statusB, ENDIAN)))
    def recv(self) -> Generator[tuple[bytes, tuple[str, int]], None, None]:
        for data, addr in super().recv():
            if len(data) < SecurePacketElementSize.PACKET_FLAG+SecurePacketElementSize.MODE_FLAG:
                continue
            pFlag, mFlag, mainData = bytesSplitter.split(
                data+b"\x00",
                SecurePacketElementSize.PACKET_FLAG,
                SecurePacketElementSize.MODE_FLAG,
                includeRest=True
            )
            mainData = mainData[:-1]
            if btoi(pFlag, ENDIAN) != PacketFlag.SECURE.value:
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
                case PacketModeFlag.RESP_HELLO:
                    target, args = self._recvRespHello, (mainData, addr)     
                case PacketModeFlag.SECOND_HELLO:
                    target, args = self._recvSecondHello, (mainData, addr)
                case PacketModeFlag.AGENCY_PING:
                    target, args = self._recvAgencyPing, (mainData, addr)
                case PacketModeFlag.RESP_AGENCY_PING:
                    target, args = self._recvRespAgencyPing, (mainData, addr)
                case _:
                    continue

            Thread(
                target=target, args=args, daemon=True
            ).start()

