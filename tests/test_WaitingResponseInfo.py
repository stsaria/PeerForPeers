import pytest
import asyncio
from P4PCore.model.WaitingResponseInfo import WaitingResponseInfo


class TestWaitingResponseInfo:
    def testCreate(self):
        info = WaitingResponseInfo(("127.0.0.1", 8080))
        assert info.identify is not None
        assert len(info.identify) == 16

    def testKey(self):
        info = WaitingResponseInfo(("127.0.0.1", 8080))
        key = info.key
        assert key[0] == ("127.0.0.1", 8080)
        assert key[1] == info.identify

    def testUniqueIdentify(self):
        info1 = WaitingResponseInfo(("127.0.0.1", 8080))
        info2 = WaitingResponseInfo(("127.0.0.1", 8080))
        assert info1.identify != info2.identify