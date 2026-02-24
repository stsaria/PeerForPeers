from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

NONCE_LEN = 12
AES_KEY_LEN = 32

def generateX25519PivKey() -> X25519PrivateKey:
    return X25519PrivateKey.generate()

def getX25519PubKeyByPubKeyBytes(key:bytes):
    return X25519PublicKey.from_public_bytes(key)

def encryptAes(key:AESGCM, data:bytes, nonce:bytes, aad:bytes | None) -> bytes:
    return key.encrypt(nonce, data, aad)

def decryptAes(key:AESGCM, encryptedData:bytes, nonce:bytes, aad:bytes | None) -> bytes | None:
    try:
        return key.decrypt(nonce, encryptedData, aad)
    except InvalidTag:
        return

def deriveSecretByX25519(otherPartyPubKey:X25519PublicKey, myPivKey:X25519PrivateKey, salt:bytes, info:bytes=b"X25519-singleUseKey") -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        info=info
    ).derive(myPivKey.exchange(otherPartyPubKey))

def deriveAesKey(secret:bytes, salt:bytes, info:bytes=b"AES256-singleUseKey") -> AESGCM:
    return AESGCM(
        HKDF(
            algorithm=SHA256(),
            length=AES_KEY_LEN,
            salt=salt,
            info=info
        ).derive(secret)
    )

def deriveBytesBySecret(secret:bytes, salt:bytes, aesInfo:bytes, length:int) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=length,
        salt=salt,
        info=aesInfo
    ).derive(secret)

def calcAllSize(plainAllSize:int) -> int:
    return 16 * (plainAllSize // 16)