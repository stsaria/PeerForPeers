import pytest
from P4PCore.model.Ed25519Signer import Ed25519Signer


class TestEd25519Signer:
    @pytest.mark.asyncio
    async def testSign(self):
        signer = Ed25519Signer()
        data = b"test data"
        sig = await signer.sign(data)
        assert isinstance(sig, bytes)
        assert len(sig) == 64

    @pytest.mark.asyncio
    async def testSignDifferentData(self):
        signer = Ed25519Signer()
        sig1 = await signer.sign(b"data1")
        sig2 = await signer.sign(b"data2")
        assert sig1 != sig2

    @pytest.mark.asyncio
    async def testPublicKey(self):
        signer = Ed25519Signer()
        pubKey = signer.publicKey
        assert pubKey is not None
        assert hasattr(pubKey, "bytesKey")

    @pytest.mark.asyncio
    async def testVerifyValidSignature(self):
        signer = Ed25519Signer()
        data = b"test data"
        sig = await signer.sign(data)
        pubKey = signer.publicKey
        result = await pubKey.verify(sig, data)
        assert result is True

    @pytest.mark.asyncio
    async def testVerifyInvalidSignature(self):
        signer = Ed25519Signer()
        data = b"test data"
        sig = await signer.sign(data)
        pubKey = signer.publicKey
        result = await pubKey.verify(sig, b"wrong data")
        assert result is False