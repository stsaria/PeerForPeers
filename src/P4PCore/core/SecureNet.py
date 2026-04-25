import os
import asyncio
import logging
from enum import auto as a
from uuid import UUID

from P4PCore.interface.ISecureNet import ISecureNet
from P4PCore.model.HashableEd25519PublicKey import HashableEd25519PublicKey
from P4PCore.PeerForPeers import PeerForPeers
from P4PCore.abstract.NetHandler import NetHandler
from P4PCore.interface.NetHandlerRegistry import NetHandlerRegistry
from P4PCore.model.Response import Response
from P4PCore.model.NodeIdentify import NodeIdentify
from P4PCore.manager.WaitingResponses import WaitingResponses
from P4PCore.model.WaitingResponse import WaitingResponse
from P4PCore.model.WaitingResponseInfo import WaitingResponseInfo, WAITING_RESPONSE_INFO_KEY
from P4PCore.core.Net import Net
from P4PCore.model.Ed25519Signer import Ed25519Signer
from P4PCore.util.BytesCoverter import *
from P4PCore.protocol.Protocol import *
from P4PCore.protocol.ProgramProtocol import *
from P4PCore.manager.SimpleImpls import SimpleCannotOverwriteKVManager, SimpleCannotDeleteAndOverwriteKVManager, SimpleSetManager
from P4PCore.model.X25519AndAesEncrypter import X25519AndAesgcmEncrypter
from P4PCore.util import BytesSplitter
from P4PCore.util.AddrLogger import AddrLogger

_logger = logging.getLogger()
_sAddrLogger = AddrLogger(_logger, True)
_rAddrLogger = AddrLogger(_logger, False)

class SecureNet(ISecureNet, NetHandler, NetHandlerRegistry):
    __ed25519Signer:Ed25519Signer
    __waitingResponses:WaitingResponses
    __encrypters:SimpleCannotOverwriteKVManager[tuple[str, int], X25519AndAesgcmEncrypter]
    __handlers:SimpleCannotDeleteAndOverwriteKVManager[UUID, NetHandler]
    _helloingAddrs:SimpleSetManager[tuple[str, int]]
    _net:Net
    @classmethod
    async def create(cls, net:Net, myEd25519Signer:Ed25519Signer) -> "SecureNet":
        inst = cls()

        inst.__ed25519Signer = myEd25519Signer

        inst.__waitingResponses = WaitingResponses()
        inst.__encrypters = SimpleCannotOverwriteKVManager()
        inst.__handlers = SimpleCannotDeleteAndOverwriteKVManager()
        inst._helloingAddrs = SimpleSetManager()

        inst._net = net

        await inst._net.registerHandler(PacketFlag.SECURE, inst)
        return inst
    async def registerHandler(self, flag:UUID, handler:NetHandler) -> bool:
        """
        Register a handler for handling secure packets with the flag of the content type.
        The content type is a UUID that identifies the type of the content of the secure packet.
        """
        return await self.__handlers.add(flag, handler)
    def getNet(self) -> Net:
        """
        Get the raw net object.
        """
        return self._net
    class HelloResult(IntEnum):
        SUCCESS = a()
        OTHER_FUNC_IS_TRYING_TO_CONNECT = a()
        ALREADY_CONNECTED = a()
        FAILED_FIRST_HI = a()
    async def hello(self, nodeIdentify:NodeIdentify) -> HelloResult:
        """
        Connect to the node and return the result of the connection.
        After calling this function, you can communicate with the node securely.
        """
        if not await self._helloingAddrs.add(nodeIdentify.addr):
            return self.HelloResult.OTHER_FUNC_IS_TRYING_TO_CONNECT
        elif await self.__encrypters.get(nodeIdentify.addr):
            return self.HelloResult.ALREADY_CONNECTED
        async with self.__waitingResponses.open(
            WaitingResponse[tuple[HashableEd25519PublicKey, bytes], tuple[bytes, bytes, bytes]](
                WaitingResponseInfo(nodeIdentify.addr),
                otherInfo=(nodeIdentify.hashableEd25519PublicKey, (cT := os.urandom(ANY_UNIQUE_RANDOM_BYTES_SIZE)))
            )
        ) as c:
            success = False
            for _ in range(HELLO_ATTEMPTS):
                self._net.sendTo(
                    (
                        itob(PacketFlag.SECURE, SecurePacketElementSize.PACKET_FLAG, ENDIAN)
                        +itob(PacketModeFlag.HELLO, SecurePacketElementSize.MODE_FLAG, ENDIAN)
                        +c.waitingResponse.waitingResponseInfo.identify
                        +cT
                        +self.__ed25519Signer.publicKey.bytesKey
                    ),
                    nodeIdentify.addr
                )
                if not (r := await c.waitingResponse.waitAndGet(TIME_OUT_SEC)) is None and not r.nextResponseId is None:
                    success = True
                    break
            if not success:
                return self.HelloResult.FAILED_FIRST_HI
        cT, oPX25519PKB, aesSalt = r.value
        e = X25519AndAesgcmEncrypter(
            True,
            salt=aesSalt
        )
        self._net.sendTo(
            (
                itob(PacketFlag.SECURE, SecurePacketElementSize.PACKET_FLAG, ENDIAN)
                +itob(PacketModeFlag.SECOND_HELLO, SecurePacketElementSize.MODE_FLAG, ENDIAN)
                +r.nextResponseId
                +(pubKeyRaw := e.myX25519PublicKeyBytes)
                +await self.__ed25519Signer.sign(cT+pubKeyRaw)
            ),
            nodeIdentify.addr
        )
        await e.derive(oPX25519PKB)
        await PeerForPeers.getAddrToEd25519PubkeysManager().add(nodeIdentify.addr, nodeIdentify.hashableEd25519PublicKey)
        await self.__encrypters.add((nodeIdentify.ip, nodeIdentify.port), e)
        return self.HelloResult.SUCCESS
    async def sendToSecure(self, data:bytes, nodeIdentify:NodeIdentify) -> bool:
        """
        Send data to the node securely and return whether the sending is successful.
        This function only returns whether the sending is successful, but it does not return whether the node has received the data.
        """
        if getMaxDataSizeOnAesEncrypted()-AESGCM_NONCE_SIZE < len(data):
            return False
        if not (e := await self.__encrypters.get(nodeIdentify.addr)):
            return False
        seq, eData = await e.encrypt(data)
        return self._net.sendTo(
            itob(PacketFlag.SECURE, SecurePacketElementSize.PACKET_FLAG, ENDIAN)
            +itob(PacketModeFlag.MAIN_DATA, SecurePacketElementSize.MODE_FLAG, ENDIAN)
            +itob(seq, SecurePacketElementSize.SEQ, ENDIAN)
            +eData,
            nodeIdentify.addr
        )

    async def getAddrs(self) -> list[tuple[str, int]]:
        return list((await self.__encrypters.getAll()).keys())
    
    async def _recvHello(self, mD:bytes, addr:tuple[str, int]) -> None:
        if not await self._helloingAddrs.add(addr):
            return
        if await self.__encrypters.get(addr):
            await self._helloingAddrs.remove(addr)
            return
        _rAddrLogger.dbg(addr, "Recved hello")
        rI, cT, ed25519PubKeyB = BytesSplitter.split(
            mD,
            SecurePacketElementSize.RESPONSE_TOKEN,
            ANY_UNIQUE_RANDOM_BYTES_SIZE,
            SecurePacketElementSize.ED25519_PUBLIC_KEY
        )
        e = X25519AndAesgcmEncrypter(False)
        async with self.__waitingResponses.open(
            WaitingResponse[tuple[bytes, bytes], bytes](
                WaitingResponseInfo(addr),
                (ed25519PubKeyB, nCT := os.urandom(ANY_UNIQUE_RANDOM_BYTES_SIZE))
            )
        ) as c:
            self._net.sendTo(
                (
                    itob(PacketFlag.SECURE, SecurePacketElementSize.PACKET_FLAG, ENDIAN)
                    +itob(PacketModeFlag.RESP_HELLO, SecurePacketElementSize.MODE_FLAG, ENDIAN)
                    +rI
                    +c.waitingResponse.waitingResponseInfo.identify
                    +(signEndPart := nCT+e.myX25519PublicKeyBytes+e.salt)
                    +await self.__ed25519Signer.sign(cT+signEndPart)
                ),
                addr
            )
            if (r := await c.waitingResponse.waitAndGet(TIME_OUT_SEC)) is None:
                await self._helloingAddrs.remove(addr)
                return
            elif r.value is None:
                await self._helloingAddrs.remove(addr)
                return
        if not await PeerForPeers.getAddrToEd25519PubkeysManager().add(addr, ed25519PubKeyB):
            await self._helloingAddrs.remove(addr)
            return
        await e.derive(r.value)
        await self.__encrypters.add(addr, e)
    async def _recvRespHello(self, mD:bytes, addr:tuple[str, int]) -> None:
        rI, nRI, nCT, x25519PubKeyB, aesSaltB, signedB = BytesSplitter.split(
            mD, 
            ANY_UNIQUE_RANDOM_BYTES_SIZE,
            ANY_UNIQUE_RANDOM_BYTES_SIZE,
            ANY_UNIQUE_RANDOM_BYTES_SIZE,
            SecurePacketElementSize.X25519_PUBLIC_KEY,
            SecurePacketElementSize.AES_SALT,
            SecurePacketElementSize.ED25519_SIGN
        )
        key:WAITING_RESPONSE_INFO_KEY = (addr, rI)
        wR:WaitingResponse[tuple[HashableEd25519PublicKey, bytes], tuple[bytes, bytes, bytes]] = await self.__waitingResponses.get(key)
        if wR is None or not wR:
            return
        otherPartyEd25519PK, cT = wR.otherInfo
        if not await otherPartyEd25519PK.verify(signedB, cT+nCT+x25519PubKeyB+aesSaltB):
            return
        wR.setResponse(Response((nCT, x25519PubKeyB, aesSaltB), nextResponseId=nRI))
    async def _recvSecondHello(self, mD:bytes, addr:tuple[str, int]) -> None:
        rI, x25519PubKeyB, signedB = BytesSplitter.split(
            mD,
            ANY_UNIQUE_RANDOM_BYTES_SIZE,
            SecurePacketElementSize.X25519_PUBLIC_KEY,
            SecurePacketElementSize.ED25519_SIGN
        )
        key:WAITING_RESPONSE_INFO_KEY = (addr, rI)
        wR:WaitingResponse[tuple[bytes, bytes], tuple[bytes, bytes]] = await self.__waitingResponses.get(key)
        if wR is None or not wR:
            return
        otherPartyEd25519PKB, cT = wR.otherInfo
        if not await HashableEd25519PublicKey.createByBytes(otherPartyEd25519PKB).verify(signedB, cT+x25519PubKeyB):
            return
        wR.setResponse(Response(x25519PubKeyB))
    async def _recvMainData(self, mD:bytes, addr:tuple[str, int]) -> None:
        seqB, eData = BytesSplitter.split(
            mD,
            SecurePacketElementSize.SEQ,
            includeRest=True
        )
        if not (e := await self.__encrypters.get(addr)):
            return
        cType, mainData = BytesSplitter.split(
            await e.decrypt(eData, btoi(seqB, ENDIAN)),
            SecurePacketElementSize.CONTENT_TYPE_UUID,
            includeRest=True
        )
        if (h := await self.__handlers.get(UUID(bytes=cType))) is None:
            return
        asyncio.create_task(h.handle(mainData, addr))
    async def handle(self, data:bytes, addr:tuple[str, int]) -> None:
        if len(data) < SecurePacketElementSize.MODE_FLAG:
            return
        mFlag, mainData = BytesSplitter.split(
            data,
            SecurePacketElementSize.MODE_FLAG,
            includeRest=True
        )
        try:
            mFlag = PacketModeFlag(btoi(mFlag, ENDIAN))
        except ValueError:
            return
        
        target = {
            PacketModeFlag.HELLO: self._recvHello,
            PacketModeFlag.RESP_HELLO: self._recvRespHello,
            PacketModeFlag.SECOND_HELLO: self._recvSecondHello,
            PacketModeFlag.MAIN_DATA: self._recvMainData
        }.get(mFlag)
        if not target:
            return
        try:
            await target(mainData, addr)
        except Exception as e:
            _logger.exception("An Exception has occurred on handle func")
        finally:
            pass

        
