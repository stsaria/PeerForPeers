import pytest
from P4PCore.model.TaskInfo import TaskInfo


class TestTaskInfo:
    def testCreate(self):
        class DummyIdentify:
            def __hash__(self):
                return 123
            def __eq__(self, other):
                return isinstance(other, DummyIdentify)

        owner = object()
        identify = DummyIdentify()
        taskInfo = TaskInfo(owner=owner, identify=identify)
        assert taskInfo.owner is owner
        assert taskInfo.identify is identify

    def testHash(self):
        class DummyIdentify:
            def __init__(self, value):
                self.value = value
            def __hash__(self):
                return hash(self.value)
            def __eq__(self, other):
                return isinstance(other, DummyIdentify) and self.value == other.value

        owner = object()
        identify = DummyIdentify(42)
        taskInfo1 = TaskInfo(owner=owner, identify=identify)
        taskInfo2 = TaskInfo(owner=owner, identify=identify)
        assert hash(taskInfo1) == hash(taskInfo2)

    def testEquality(self):
        class DummyIdentify:
            def __init__(self, value):
                self.value = value
            def __hash__(self):
                return hash(self.value)
            def __eq__(self, other):
                return isinstance(other, DummyIdentify) and self.value == other.value

        owner = object()
        identify = DummyIdentify(42)
        taskInfo1 = TaskInfo(owner=owner, identify=identify)
        taskInfo2 = TaskInfo(owner=owner, identify=identify)
        assert taskInfo1 == taskInfo2

    def testInequality(self):
        class DummyIdentify:
            def __init__(self, value):
                self.value = value
            def __hash__(self):
                return hash(self.value)
            def __eq__(self, other):
                return isinstance(other, DummyIdentify) and self.value == other.value

        owner = object()
        identify1 = DummyIdentify(42)
        identify2 = DummyIdentify(99)
        taskInfo1 = TaskInfo(owner=owner, identify=identify1)
        taskInfo2 = TaskInfo(owner=owner, identify=identify2)
        assert taskInfo1 != taskInfo2