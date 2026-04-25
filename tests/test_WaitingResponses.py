import pytest
import asyncio
from P4PCore.manager.WaitingResponses import WaitingResponses
from P4PCore.model.WaitingResponse import WaitingResponse
from P4PCore.model.WaitingResponseInfo import WaitingResponseInfo
from P4PCore.model.Response import Response


class TestWaitingResponses:
    @pytest.mark.asyncio
    async def testCreate(self):
        manager = WaitingResponses()
        assert manager is not None

    @pytest.mark.asyncio
    async def testOpen(self):
        manager = WaitingResponses()
        info = WaitingResponseInfo(("127.0.0.1", 8080))
        waiting = WaitingResponse[str, str](info)
        
        async with manager.open(waiting) as context:
            assert context.waitingResponse is waiting
        
        result = await manager.get(info.key)
        assert result is None

    @pytest.mark.asyncio
    async def testGet(self):
        manager = WaitingResponses()
        info = WaitingResponseInfo(("127.0.0.1", 8080))
        waiting = WaitingResponse[str, str](info)
        
        async with manager.open(waiting):
            result = await manager.get(info.key)
            assert result is waiting

    @pytest.mark.asyncio
    async def testContextManager(self):
        manager = WaitingResponses()
        info = WaitingResponseInfo(("127.0.0.1", 8080))
        waiting = WaitingResponse[str, str](info)
        
        async with manager.open(waiting) as context:
            assert context._exited is False
        
        assert context._exited is True