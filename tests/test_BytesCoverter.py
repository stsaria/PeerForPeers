import pytest
from P4PCore.util.BytesCoverter import itob, btoi, stob, btos
from enum import IntEnum


class TestItob:
    def testPositiveIntLittleEndian(self):
        result = itob(256, 2, "little")
        assert result == b"\x00\x01"

    def testPositiveIntBigEndian(self):
        result = itob(256, 2, "big")
        assert result == b"\x01\x00"

    def testSignedInt(self):
        result = itob(-1, 2, "big", signed=True)
        assert result == b"\xff\xff"

    def testIntEnum(self):
        class TestEnum(IntEnum):
            VALUE = 42

        result = itob(TestEnum.VALUE, 1, "big")
        assert result == b"*"


class TestBtoi:
    def testLittleEndian(self):
        result = btoi(b"\x00\x01", "little")
        assert result == 256

    def testBigEndian(self):
        result = btoi(b"\x01\x00", "big")
        assert result == 256

    def testSigned(self):
        result = btoi(b"\xff\xff", "big", signed=True)
        assert result == -1


class TestStob:
    def testNormalString(self):
        result = stob("hello", 10, "utf-8")
        assert result == b"hello\x00\x00\x00\x00\x00"

    def testTruncateLongString(self):
        result = stob("hello world", 5, "utf-8")
        assert result == b"hello"

    def testEmptyString(self):
        result = stob("", 5, "utf-8")
        assert result == b"\x00\x00\x00\x00\x00"


class TestBtos:
    def testNormalBytes(self):
        result = btos(b"hello\x00\x00", "utf-8")
        assert result == "hello"

    def testNoPadding(self):
        result = btos(b"hello", "utf-8")
        assert result == "hello"