import pytest
from P4PCore.model.NetConfig import NetConfig


class TestNetConfig:
    def testCreate(self):
        config = NetConfig(addrV4=("127.0.0.1", 8080), addrV6=("::1", 8080))
        assert config.addrV4 == ("127.0.0.1", 8080)
        assert config.addrV6 == ("::1", 8080)

    def testCreateWithNone(self):
        config = NetConfig(addrV4=None, addrV6=None)
        assert config.addrV4 is None
        assert config.addrV6 is None