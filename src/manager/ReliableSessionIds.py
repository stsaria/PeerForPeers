from threading import Condition, Lock
from interface.Manager import TicketingManager
from protocol.Protocol import ENDIAN, RELIABLE_SESSION_ID_SIZE, ReliablePacketElementSize
from util.bytesCoverter import itob

class ReliableSessionIds(TicketingManager):
    usedIds:set[bytes] = set()
    usedIdsCond:Condition = Condition()

    @classmethod
    def waitAndIssueTicket(cls) -> bytes:
        with cls.usedIdsCond:
            while True:
                for i in range(0, 2**(ReliablePacketElementSize.SESSION_ID * 8)):
                    if not (sessionId := itob(i, ReliablePacketElementSize.SESSION_ID, ENDIAN)) in cls.usedIds:
                        cls.usedIds.add(sessionId)
                        return sessionId
                cls.usedIdsCond.wait()
    @classmethod
    def dropTicket(cls, ticket:bytes) -> None:
        with cls.usedIdsCond:
            if ticket in cls.usedIds:
                cls.usedIds.remove(ticket)
                cls.usedIdsCond.notify_all()