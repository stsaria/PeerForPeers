import pytest
import asyncio
from P4PCore.model.WaitingResponse import WaitingResponse
from P4PCore.model.WaitingResponseInfo import WaitingResponseInfo
from P4PCore.model.Response import Response


class TestWaitingResponse:
    @pytest.mark.asyncio
    async def testCreate(self):
        info = WaitingResponseInfo(("127.0.0.1", 8080))
        waiting = WaitingResponse[str, str](info)
        assert waiting.waitingResponseInfo is info
        assert waiting.otherInfo is None

    @pytest.mark.asyncio
    async def testCreateWithOtherInfo(self):
        info = WaitingResponseInfo(("127.0.0.1", 8080))
        waiting = WaitingResponse[str, str](info, otherInfo="test")
        assert waiting.otherInfo == "test"

    @pytest.mark.asyncio
    async def testSetResponse(self):
        info = WaitingResponseInfo(("127.0.0.1", 8080))
        waiting = WaitingResponse[str, str](info)
        response = Response("result")
        result = waiting.setResponse(response)
        assert result is True

    @pytest.mark.asyncio
    async def testSetResponseTwice(self):
        info = WaitingResponseInfo(("127.0.0.1", 8080))
        waiting = WaitingResponse[str, str](info)
        response1 = Response("result1")
        response2 = Response("result2")
        result1 = waiting.setResponse(response1)
        result2 = waiting.setResponse(response2)
        assert result1 is True
        assert result2 is False

    @pytest.mark.asyncio
    async def testWaitAndGet(self):
        info = WaitingResponseInfo(("127.0.0.1", 8080))
        waiting = WaitingResponse[str, str](info)
        
        async def set_response():
            await asyncio.sleep(0.01)
            waiting.setResponse(Response("result"))
        
        task = asyncio.create_task(set_response())
        result = await waiting.waitAndGet()
        assert result.value == "result"
        await task

    @pytest.mark.asyncio
    async def testWaitAndGetWithTimeout(self):
        info = WaitingResponseInfo(("127.0.0.1", 8080))
        waiting = WaitingResponse[str, str](info)
        
        result = await waiting.waitAndGet(timeoutSec=0.01)
        assert result is None

    @pytest.mark.asyncio
    async def testBool(self):
        info = WaitingResponseInfo(("127.0.0.1", 8080))
        waiting = WaitingResponse[str, str](info)
        assert bool(waiting) is True
        
        waiting.setResponse(Response("result"))
        assert bool(waiting) is False