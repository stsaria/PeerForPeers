import os
import asyncio
import logging
from enum import auto as a
from typing import TypeVar
from uuid import UUID

from P4PCore.interface.IP4PRunner import IP4PRunner
from P4PCore.interface.ISecureNet import ISecureNet
from P4PCore.model.HashableEd25519PublicKey import HashableEd25519PublicKey
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

class SecureNet(ISecureNet, NetHandler, NetHandlerRegistry):
    _runner:IP4PRunner
    _net:Net
    _ed25519Signer:Ed25519Signer
    _waitingResponses:WaitingResponses
    _encrypters:SimpleCannotOverwriteKVManager[tuple[str, int], X25519AndAesgcmEncrypter]
    _handlers:SimpleCannotDeleteAndOverwriteKVManager[UUID, NetHandler]
    _helloingAddrs:SimpleSetManager[tuple[str, int]]
    _sAddrLogger:AddrLogger
    _rAddrLogger:AddrLogger
    @classmethod
    async def create(cls, net:Net, myEd25519Signer:Ed25519Signer) -> "SecureNet":
        inst = cls()

        inst._net = net
        inst._ed25519Signer = myEd25519Signer
        inst._waitingResponses = WaitingResponses()
        inst._encrypters = SimpleCannotOverwriteKVManager()
        inst._handlers = SimpleCannotDeleteAndOverwriteKVManager()
        inst._helloingAddrs = SimpleSetManager()

        await inst._net.registerHandler(PacketFlag.SECURE, inst)
        return inst
    async def setRunner(self, runner:IP4PRunner):
        self._runner = runner

        logger = await self._runner.getLogger(__name__)
        self._sAddrLogger = AddrLogger(logger, True)
        self._rAddrLogger = AddrLogger(logger, False)
    async def registerHandler(self, flag:UUID, handler:NetHandler) -> bool:
        return await self._handlers.add(flag, handler)
    @property
    def rawNet(self) -> Net:
        return self._net
    async def hello(self, nodeIdentify:NodeIdentify) -> ISecureNet.HelloResult:
        self._sAddrLogger.dbg(nodeIdentify.addr, "Trying hello.")
        if not await self._helloingAddrs.add(nodeIdentify.addr):
            self._sAddrLogger.warn(nodeIdentify.addr, "Failed to try hello, other function is already trying.")
            return self.HelloResult.OTHER_FUNC_IS_ALREADY_TRYING_TO_CONNECT
        elif await self._encrypters.get(nodeIdentify.addr):
            self._sAddrLogger.warn(nodeIdentify.addr, "Failed to try hello, the node is already connected.")
            return self.HelloResult.ALREADY_CONNECTED
        async with self._waitingResponses.open(
            WaitingResponse[tuple[HashableEd25519PublicKey, bytes], tuple[bytes, bytes, bytes]](
                WaitingResponseInfo(nodeIdentify.addr),
                otherInfo=(nodeIdentify.hashableEd25519PublicKey, (cT := os.urandom(ANY_UNIQUE_RANDOM_BYTES_SIZE)))
            )
        ) as c:
            success = False
            for _ in range(HELLO_SEND_VOLUME):
                self._net.sendTo(
                    (
                        itob(PacketFlag.SECURE, SecurePacketElementSize.PACKET_FLAG, ENDIAN)
                        +itob(ModeFlag.HELLO, SecurePacketElementSize.MODE_FLAG, ENDIAN)
                        +c.waitingResponse.waitingResponseInfo.identify
                        +cT
                        +self._ed25519Signer.publicKey.bytesKey
                    ),
                    nodeIdentify.addr
                )
                if not (r := await c.waitingResponse.waitAndGet(TIME_OUT_SEC)) is None and not r.nextResponseId is None:
                    success = True
                    break
            if not success:
                self._sAddrLogger.warn(nodeIdentify.addr, "Failed to try hello, the node didn't respond.")
                return self.HelloResult.FAILED_FIRST_HI
        cT, oPX25519PKB, aesSalt = r.value
        e = X25519AndAesgcmEncrypter(
            True,
            salt=aesSalt
        )
        for _ in range(HELLO_SEND_VOLUME):
            self._net.sendTo(
                (
                    itob(PacketFlag.SECURE, SecurePacketElementSize.PACKET_FLAG, ENDIAN)
                    +itob(ModeFlag.SECOND_HELLO, SecurePacketElementSize.MODE_FLAG, ENDIAN)
                    +r.nextResponseId
                    +(pubKeyRaw := e.myX25519PublicKeyBytes)
                    +await self._ed25519Signer.sign(cT+pubKeyRaw)
                ),
                nodeIdentify.addr
            )
        await e.derive(oPX25519PKB)
        await self._runner.addrToEd25519PubkeysManager.add(nodeIdentify.addr, nodeIdentify.hashableEd25519PublicKey)
        await self._encrypters.add((nodeIdentify.ip, nodeIdentify.port), e)

        return self.HelloResult.SUCCESS
    async def sendToSecure(self, data:bytes, to:tuple[str, int] | NodeIdentify) -> bool:
        if isinstance(to, NodeIdentify):
            to = to.addr
        if getMaxDataSizeOnAesEncrypted()-AESGCM_NONCE_SIZE < len(data):
            return False
        if not (e := await self._encrypters.get(to)):
            return False
        seq, eData = await e.encrypt(data)
        return self._net.sendTo(
            itob(PacketFlag.SECURE, SecurePacketElementSize.PACKET_FLAG, ENDIAN)
            +itob(ModeFlag.MAIN_DATA, SecurePacketElementSize.MODE_FLAG, ENDIAN)
            +itob(seq, SecurePacketElementSize.SEQ, ENDIAN)
            +eData,
            to
        )
    async def deleteNode(self, node:tuple[str, int] | NodeIdentify) -> bool:
        await self._encrypters.delete(node.addr if isinstance(node, NodeIdentify) else node)

    async def getAddrs(self) -> list[tuple[str, int]]:
        return list((await self._encrypters.getAll()).keys())
    
    async def _recvHello(self, mD:bytes, addr:tuple[str, int]) -> None:
        if not await self._helloingAddrs.add(addr):
            return
        if await self._encrypters.get(addr):
            await self._helloingAddrs.remove(addr)
            return
        self._rAddrLogger.dbg(addr, "Recved hello")
        rI, cT, ed25519PubKeyB = BytesSplitter.split(
            mD,
            SecurePacketElementSize.RESPONSE_IDENTIFY,
            ANY_UNIQUE_RANDOM_BYTES_SIZE,
            SecurePacketElementSize.ED25519_PUBLIC_KEY
        )
        e = X25519AndAesgcmEncrypter(False)
        async with self._waitingResponses.open(
            WaitingResponse[tuple[bytes, bytes], bytes](
                WaitingResponseInfo(addr),
                (ed25519PubKeyB, nCT := os.urandom(ANY_UNIQUE_RANDOM_BYTES_SIZE))
            )
        ) as c:
            for _ in range(HELLO_SEND_VOLUME):
                self._net.sendTo(
                    (
                        itob(PacketFlag.SECURE, SecurePacketElementSize.PACKET_FLAG, ENDIAN)
                        +itob(ModeFlag.RESP_HELLO, SecurePacketElementSize.MODE_FLAG, ENDIAN)
                        +rI
                        +c.waitingResponse.waitingResponseInfo.identify
                        +(signEndPart := nCT+e.myX25519PublicKeyBytes+e.salt)
                        +await self._ed25519Signer.sign(cT+signEndPart)
                    ),
                    addr
                )
                if (r := await c.waitingResponse.waitAndGet(TIME_OUT_SEC)) and r.value:
                    await self._helloingAddrs.remove(addr)
                    break
        if not await self._runner.addrToEd25519PubkeysManager.add(addr, ed25519PubKeyB):
            await self._helloingAddrs.remove(addr)
            return
        await e.derive(r.value)
        await self._encrypters.add(addr, e)
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
        wR:WaitingResponse[tuple[HashableEd25519PublicKey, bytes], tuple[bytes, bytes, bytes]] = await self._waitingResponses.get(key)
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
        wR:WaitingResponse[tuple[bytes, bytes], tuple[bytes, bytes]] = await self._waitingResponses.get(key)
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
        if not (e := await self._encrypters.get(addr)):
            return
        cI, mainData = BytesSplitter.split(
            await e.decrypt(eData, btoi(seqB, ENDIAN)),
            SecurePacketElementSize.CONTENT_UUID,
            includeRest=True
        )
        if (h := await self._handlers.get(UUID(bytes=cI))) is None:
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
            mFlag = ModeFlag(btoi(mFlag, ENDIAN))
        except ValueError:
            return
        
        target = {
            ModeFlag.HELLO: self._recvHello,
            ModeFlag.RESP_HELLO: self._recvRespHello,
            ModeFlag.SECOND_HELLO: self._recvSecondHello,
            ModeFlag.MAIN_DATA: self._recvMainData,
        }.get(mFlag)
        if not target:
            return
        try:
            await target(mainData, addr)
        except Exception as e:
            self._rAddrLogger.warn()
            self._rAddrLogger.exception("An Exception has occurred on handle func")
        finally:
            pass
