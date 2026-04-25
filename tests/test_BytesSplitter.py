import pytest
from P4PCore.util.BytesSplitter import split

class TestSplit:
    def testNormalSplit(self):
        data = b"0123456789"
        result = split(data, 2, 3, 4)
        assert result == [b"01", b"234", b"5678"]

    def testWithIncludeRest(self):
        data = b"0123456789"
        result = split(data, 2, 3, 4, includeRest=True)
        assert result == [b"01", b"234", b"5678", b"9"]

    def testDataTooShort(self):
        data = b"abc"
        with pytest.raises(ValueError, match="Data too short"):
            split(data, 5, 5)

    def testExactSize(self):
        data = b"abcdef"
        result = split(data, 2, 4)
        assert result == [b"ab", b"cdef"]

    def testEmptyData(self):
        data = b""
        with pytest.raises(ValueError, match="Data too short"):
            split(data, 1)