from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

def generatePivKey() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()

def getPivKeyByPivKeyBytes(pivKeyB:bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(pivKeyB)

def getPubKeyByPubKeyBytes(pubKeyB:bytes) -> Ed25519PrivateKey:
    return Ed25519PublicKey.from_public_bytes(pubKeyB)

def sign(data:bytes, pivKey:Ed25519PrivateKey) -> bytes:
    return pivKey.sign(data)

def verify(data:bytes, sig:bytes, pubKey:Ed25519PublicKey) -> bool:
    try:
        pubKey.verify(bytes.fromhex(sig), data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False