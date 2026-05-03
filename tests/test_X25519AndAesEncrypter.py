from P4PCore.protocol.ProgramProtocol import ENCRYPTER_OTHER_PARTY_SEQ_WINDOW
from cryptography.exceptions import InvalidTag
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from P4PCore.model.X25519AndAesEncrypter import X25519AndAesgcmEncrypter


class TestX25519AndAesgcmEncrypter:
    @pytest.mark.asyncio
    async def testDerive(self):
        encrypter1 = X25519AndAesgcmEncrypter(True)
        encrypter2 = X25519AndAesgcmEncrypter(False, salt=encrypter1.salt)

        pubKeyB1 = encrypter1._myX25519PrivateKey.public_key().public_bytes_raw()
        pubKeyB2 = encrypter2._myX25519PrivateKey.public_key().public_bytes_raw()

        await encrypter1.derive(pubKeyB2)
        await encrypter2.derive(pubKeyB1)

        assert encrypter1._sharedSecret == encrypter2._sharedSecret

    @pytest.mark.asyncio
    async def testEncryptDecrypt(self):
        encrypter1 = X25519AndAesgcmEncrypter(True)
        encrypter2 = X25519AndAesgcmEncrypter(False, salt=encrypter1.salt)

        pubKeyB1 = encrypter1._myX25519PrivateKey.public_key().public_bytes_raw()
        pubKeyB2 = encrypter2._myX25519PrivateKey.public_key().public_bytes_raw()

        await encrypter1.derive(pubKeyB2)
        await encrypter2.derive(pubKeyB1)

        data = b"hello world"
        s, encrypted = await encrypter1.encrypt(data)
        decrypted = await encrypter2.decrypt(encrypted, s)
        assert decrypted == data

    @pytest.mark.asyncio
    async def testEncryptWithoutDerive(self):
        encrypter = X25519AndAesgcmEncrypter(True)
        with pytest.raises(Exception):
            await encrypter.encrypt(b"data")

    @pytest.mark.asyncio
    async def testDecryptWithoutDerive(self):
        encrypter = X25519AndAesgcmEncrypter(True)
        with pytest.raises(Exception):
            await encrypter.decrypt(b"encrypted", 1)

    @pytest.mark.asyncio
    async def testDecryptInvalidData(self):
        encrypter1 = X25519AndAesgcmEncrypter(True)
        encrypter2 = X25519AndAesgcmEncrypter(False, salt=encrypter1.salt)

        pubKeyB1 = encrypter1._myX25519PrivateKey.public_key().public_bytes_raw()
        pubKeyB2 = encrypter2._myX25519PrivateKey.public_key().public_bytes_raw()

        await encrypter1.derive(pubKeyB2)
        await encrypter2.derive(pubKeyB1)

        result = await encrypter2.decrypt(b"invalid data", 1)
        assert result is None
    
    @pytest.mark.asyncio
    async def testDecryptWithWrongSeq(self):
        encrypter1 = X25519AndAesgcmEncrypter(True)
        encrypter2 = X25519AndAesgcmEncrypter(False, salt=encrypter1.salt)

        pubKeyB1 = encrypter1._myX25519PrivateKey.public_key().public_bytes_raw()
        pubKeyB2 = encrypter2._myX25519PrivateKey.public_key().public_bytes_raw()

        await encrypter1.derive(pubKeyB2)
        await encrypter2.derive(pubKeyB1)

        data = b"hello world"
        s, encrypted = await encrypter1.encrypt(data)
        result = await encrypter2.decrypt(encrypted, s+1)  # Wrong sequence number
        assert result is None

    @pytest.mark.asyncio
    async def testMultipleEncryptions(self):
        encrypter1 = X25519AndAesgcmEncrypter(True)
        encrypter2 = X25519AndAesgcmEncrypter(False, salt=encrypter1.salt)

        pubKeyB1 = encrypter1._myX25519PrivateKey.public_key().public_bytes_raw()
        pubKeyB2 = encrypter2._myX25519PrivateKey.public_key().public_bytes_raw()

        await encrypter1.derive(pubKeyB2)
        await encrypter2.derive(pubKeyB1)

        data1 = b"first message"
        data2 = b"second message"
        data3 = b"third message"

        s1, enc1 = await encrypter1.encrypt(data1)
        s2, enc2 = await encrypter1.encrypt(data2)
        s3, enc3 = await encrypter1.encrypt(data3)

        assert await encrypter2.decrypt(enc1, s1) == data1
        assert await encrypter2.decrypt(enc2, s2) == data2
        assert await encrypter2.decrypt(enc3, s3) == data3
    
    @pytest.mark.asyncio
    async def testDecryptWithUnorderSeqs(self):
        encrypter1 = X25519AndAesgcmEncrypter(True)
        encrypter2 = X25519AndAesgcmEncrypter(False, salt=encrypter1.salt)

        pubKeyB1 = encrypter1._myX25519PrivateKey.public_key().public_bytes_raw()
        pubKeyB2 = encrypter2._myX25519PrivateKey.public_key().public_bytes_raw()

        await encrypter1.derive(pubKeyB2)
        await encrypter2.derive(pubKeyB1)

        data1 = b"first message"
        data2 = b"second message"

        s1, enc1 = await encrypter1.encrypt(data1)
        s2, enc2 = await encrypter1.encrypt(data2)


        assert await encrypter2.decrypt(enc2, s2) == data2
        assert await encrypter2.decrypt(enc1, s1) == data1
    
    @pytest.mark.asyncio
    async def testDecryptWithUnorderSeqsButOutOfWindow(self):
        encrypter1 = X25519AndAesgcmEncrypter(True)
        encrypter2 = X25519AndAesgcmEncrypter(False, salt=encrypter1.salt)

        pubKeyB1 = encrypter1._myX25519PrivateKey.public_key().public_bytes_raw()
        pubKeyB2 = encrypter2._myX25519PrivateKey.public_key().public_bytes_raw()

        await encrypter1.derive(pubKeyB2)
        await encrypter2.derive(pubKeyB1)

        w = ENCRYPTER_OTHER_PARTY_SEQ_WINDOW

        encs = [
            ((data := f"{i}st message".encode(),) + await encrypter1.encrypt(data))
            for i in range(w+1)
        ]
        encs.reverse()

        for i in range(w+1):
            enc = encs[i]
            assert await encrypter2.decrypt(enc[2], enc[1]) == (None if i == w else enc[0])
