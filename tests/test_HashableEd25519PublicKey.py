import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from P4PCore.model.HashableEd25519PublicKey import HashableEd25519PublicKey


class TestHashableEd25519PublicKey:
    @pytest.mark.asyncio
    async def testCreateByKey(self):
        privateKey = Ed25519PrivateKey.generate()
        pubKey = privateKey.public_key()
        hashablePubKey = HashableEd25519PublicKey(pubKey)
        assert hashablePubKey.bytesKey is not None
        assert len(hashablePubKey.bytesKey) == 32

    @pytest.mark.asyncio
    async def testCreateByBytes(self):
        privateKey = Ed25519PrivateKey.generate()
        pubKey = privateKey.public_key()
        pubKeyBytes = pubKey.public_bytes_raw()
        hashablePubKey = HashableEd25519PublicKey.createByBytes(pubKeyBytes)
        assert hashablePubKey.bytesKey == pubKeyBytes

    @pytest.mark.asyncio
    async def testHash(self):
        privateKey = Ed25519PrivateKey.generate()
        pubKey = privateKey.public_key()
        hashablePubKey = HashableEd25519PublicKey(pubKey)
        h1 = hash(hashablePubKey)
        h2 = hash(hashablePubKey)
        assert h1 == h2

    @pytest.mark.asyncio
    async def testEquality(self):
        privateKey = Ed25519PrivateKey.generate()
        pubKey = privateKey.public_key()
        hashablePubKey1 = HashableEd25519PublicKey(pubKey)
        hashablePubKey2 = HashableEd25519PublicKey(pubKey)
        assert hashablePubKey1 == hashablePubKey2

    @pytest.mark.asyncio
    async def testInequality(self):
        privateKey1 = Ed25519PrivateKey.generate()
        privateKey2 = Ed25519PrivateKey.generate()
        hashablePubKey1 = HashableEd25519PublicKey(privateKey1.public_key())
        hashablePubKey2 = HashableEd25519PublicKey(privateKey2.public_key())
        assert hashablePubKey1 != hashablePubKey2

    @pytest.mark.asyncio
    async def testVerifyValid(self):
        privateKey = Ed25519PrivateKey.generate()
        pubKey = privateKey.public_key()
        hashablePubKey = HashableEd25519PublicKey(pubKey)
        data = b"test data"
        signature = privateKey.sign(data)
        result = await hashablePubKey.verify(signature, data)
        assert result is True

    @pytest.mark.asyncio
    async def testVerifyInvalid(self):
        privateKey1 = Ed25519PrivateKey.generate()
        privateKey2 = Ed25519PrivateKey.generate()
        pubKey = privateKey1.public_key()
        hashablePubKey = HashableEd25519PublicKey(pubKey)
        data = b"test data"
        signature = privateKey2.sign(data)
        result = await hashablePubKey.verify(signature, data)
        assert result is False