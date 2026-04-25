import pytest
from P4PCore.model.Response import Response


class TestResponse:
    def testCreate(self):
        response = Response("value")
        assert response.value == "value"
        assert response.nextResponseId is None

    def testCreateWithNextResponseId(self):
        response = Response("value", nextResponseId=b"next123")
        assert response.value == "value"
        assert response.nextResponseId == b"next123"

    def testValueTypes(self):
        response1 = Response(42)
        assert response1.value == 42

        response2 = Response([1, 2, 3])
        assert response2.value == [1, 2, 3]

        response3 = Response({"key": "value"})
        assert response3.value == {"key": "value"}