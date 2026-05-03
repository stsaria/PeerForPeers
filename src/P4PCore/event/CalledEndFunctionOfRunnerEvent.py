from P4PCore.abstract.P4PEvent import P4PEvent

class CalledEndFunctionOfRunnerEvent(P4PEvent):
    @staticmethod
    def isAsync() -> bool:
        return True