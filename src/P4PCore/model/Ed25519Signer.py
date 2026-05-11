import asyncio

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from P4PCore.model.HashableEd25519PublicKey import HashableEd25519PublicKey

class Ed25519Signer:
    def __init__(self, ed25519PrivateKeyBytes:bytes | None = None):
        self._ed25519PrivateKey:Ed25519PrivateKey = Ed25519PrivateKey.generate() if ed25519PrivateKeyBytes is None else Ed25519PrivateKey.from_private_bytes(ed25519PrivateKeyBytes)
    async def sign(self, data:bytes) -> bytes:
        return await asyncio.to_thread(self._ed25519PrivateKey.sign, data)
    @property
    def publicKey(self) -> HashableEd25519PublicKey:
        return HashableEd25519PublicKey(self._ed25519PrivateKey.public_key())