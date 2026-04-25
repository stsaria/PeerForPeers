from P4PCore.P4PRunner import P4PRunner
import pytest
import asyncio
from P4PCore.event.P4PRunnerBeginReqEvent import P4PRunnerBeginReqEvent
from P4PCore.event.P4PRunnerEndReqEvent import P4PRunnerEndReqEvent
from P4PCore.event.P4PRunnerGetSecureNetEvent import P4PRunnerGetSecureNetEvent
from P4PCore.event.P4PRunnerReBeginReqEvent import P4PRunnerReBeginReqEvent

P4PRunner()

class TestP4PRunnerGetSecureNetEvent:
    @pytest.mark.asyncio
    async def testSetAndWait(self):
        from P4PCore.interface.ISecureNet import ISecureNet

        event = P4PRunnerGetSecureNetEvent()

        class DummySecureNet(ISecureNet):
            pass

        secureNet = DummySecureNet()
        event.setSecureNet(secureNet)

        result = await event.waitAndGet()
        assert result is secureNet

    @pytest.mark.asyncio
    async def testSetAfterTimeout(self):
        from P4PCore.interface.ISecureNet import ISecureNet

        event = P4PRunnerGetSecureNetEvent()

        class DummySecureNet(ISecureNet):
            pass

        secureNet = DummySecureNet()
        event.setSecureNet(secureNet)

        result = await event.waitAndGet()
        assert result is secureNet