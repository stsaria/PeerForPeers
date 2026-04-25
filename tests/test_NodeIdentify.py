import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from P4PCore.model.NodeIdentify import NodeIdentify
from P4PCore.model.HashableEd25519PublicKey import HashableEd25519PublicKey


class TestNodeIdentify:
    def testCreate(self):
        privateKey = Ed25519PrivateKey.generate()
        pubKey = HashableEd25519PublicKey(privateKey.public_key())
        node = NodeIdentify(ip="127.0.0.1", port=8080, hashableEd25519PublicKey=pubKey)
        assert node.ip == "127.0.0.1"
        assert node.port == 8080

    def testAddr(self):
        privateKey = Ed25519PrivateKey.generate()
        pubKey = HashableEd25519PublicKey(privateKey.public_key())
        node = NodeIdentify(ip="127.0.0.1", port=8080, hashableEd25519PublicKey=pubKey)
        assert node.addr == ("127.0.0.1", 8080)

    def testHash(self):
        privateKey = Ed25519PrivateKey.generate()
        pubKey = HashableEd25519PublicKey(privateKey.public_key())
        node1 = NodeIdentify(ip="127.0.0.1", port=8080, hashableEd25519PublicKey=pubKey)
        node2 = NodeIdentify(ip="127.0.0.1", port=8080, hashableEd25519PublicKey=pubKey)
        assert hash(node1) == hash(node2)

    def testEquality(self):
        privateKey = Ed25519PrivateKey.generate()
        pubKey = HashableEd25519PublicKey(privateKey.public_key())
        node1 = NodeIdentify(ip="127.0.0.1", port=8080, hashableEd25519PublicKey=pubKey)
        node2 = NodeIdentify(ip="127.0.0.1", port=8080, hashableEd25519PublicKey=pubKey)
        assert node1 == node2

    def testInequality(self):
        privateKey1 = Ed25519PrivateKey.generate()
        privateKey2 = Ed25519PrivateKey.generate()
        pubKey1 = HashableEd25519PublicKey(privateKey1.public_key())
        pubKey2 = HashableEd25519PublicKey(privateKey2.public_key())
        node1 = NodeIdentify(ip="127.0.0.1", port=8080, hashableEd25519PublicKey=pubKey1)
        node2 = NodeIdentify(ip="127.0.0.1", port=8080, hashableEd25519PublicKey=pubKey2)
        assert node1 != node2