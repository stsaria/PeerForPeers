import pytest
from P4PCore.protocol.Protocol import getMaxDataSizeOnAesEncrypted

class TestGetMaxDataSizeOnAesEncrypted:
    def testWithoutXxhash(self):
        result = getMaxDataSizeOnAesEncrypted(False)
        assert result > 0

    def testWithXxhash(self):
        result = getMaxDataSizeOnAesEncrypted(True)
        assert result > 0
        assert result < getMaxDataSizeOnAesEncrypted(False)