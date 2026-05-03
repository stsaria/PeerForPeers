from P4PCore.abstract.P4PEvent import P4PEvent

class CalledBeginFunctionOfRunnerEvent(P4PEvent):
    @staticmethod
    def isAsync() -> bool:
        return True