# For Global
import logging
from enum import Enum

from src.protocol.Protocol import *
from src.app.protocol.Protocol import *
from src.app.model.Message import Message, ReplyMessage
from src.app.protocol.ProgramProtocol import *
from src.app.util.Db import Db

logger = logging.getLogger(__name__)

class MessagePutStatus(Enum):
    SUCCESS = 0
    MESSAGE_ID_SIZE_IS_WRONG = 1
    CONTENT_SIZE_IS_TOO_BIG = 2

MyMessageSqlType = tuple[bytes, str, int]

AllMessageType = Message
AllMessageSqlType = MyMessageSqlType

from typing import Generic, TypeVar, Iterable

ModelT = TypeVar("ModelT")
RowT = TypeVar("RowT", bound=tuple)
PrimaryKeyT = TypeVar("PrimaryKeyT")

class BaseDb(Generic[ModelT, RowT, PrimaryKeyT]):
    _db: Db
    KEY_NAME: str
    TABLE: str
    
    MODEL: type[ModelT]

    @classmethod
    def _rowToModel(cls, row: RowT) -> ModelT | None:
        try:
            return cls.MODEL(*row)
        except TypeError:
            logger.error(
                f"{cls.TABLE}: Row -> Model failed (row={str(row)})",
                exc_info=True,
            )
            return None

    @classmethod
    def get(cls, key:PrimaryKeyT, *, raw:bool=False):
        row = cls._db.fetchOne(
            f"SELECT * FROM {cls.TABLE} WHERE {cls.KEY_NAME} = ?",
            (key,)
        )
        return row if raw else cls._rowToModel(row)

    @classmethod
    def getAll(cls, *, raw: bool = False):
        rows = cls._db.fetchAll(f"SELECT * FROM {cls.TABLE}")
        if raw:
            return rows
        return [cls._rowToModel(r) for r in rows]

    @classmethod
    def getRandom(cls, limit: int = 1, *, raw: bool = False):
        rows = cls._db.fetchAll(
            f"SELECT * FROM {cls.TABLE} ORDER BY RANDOM() LIMIT ?",
            (limit,)
        )
        if raw:
            return rows
        return [cls._rowToModel(r) for r in rows]
    
class Messages(BaseDb[AllMessageType, AllMessageSqlType, bytes]):
    @classmethod
    def put(cls, messageId:bytes, message:AllMessageType) -> MessagePutStatus:
        if len(messageId) != GlobalAppElementSize.MESSAGE_ID:
            logger.warning(f"{cls.TABLE}.put: invalid messageId size ({len(messageId)})")
            return MessagePutStatus.MESSAGE_ID_SIZE_IS_WRONG
        if len(message.content.encode(STR_ENCODING)) > GlobalAppElementSize.MESSAGE_CONTENT:
            return MessagePutStatus.CONTENT_SIZE_IS_TOO_BIG

        sqlMsg = message.getSqlMsg()
        cls._db.execAndCommit(
            f"INSERT INTO {cls.TABLE} VALUES ("+(", ".join(["?" for _ in range(len(sqlMsg))]))+")",
            sqlMsg
        )
        return MessagePutStatus.SUCCESS

class MyMessages(Messages):
    _db = Db(DB_FILE)

    TABLE = "myMessages"
    KEY_NAME = "messageId"
    MODEL = Message

    _db.execAndCommit("""
        CREATE TABLE IF NOT EXISTS myMessages (
            messageId BLOB PRIMARY KEY,
            content TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        )
    """)

class ReplyMessages(Messages):
    _db = Db(DB_FILE)

    TABLE = "replyMessages"
    KEY_NAME = "messageId"
    MODEL = ReplyMessage

    _db.execAndCommit("""
        CREATE TABLE IF NOT EXISTS replyMessages (
            messageId BLOB PRIMARY KEY,
            rootMessageId BLOB NOT NULL,
            content TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        )
    """)

class ReplyRootMessages(Messages):
    _db = Db(DB_FILE)

    TABLE = "replyRootMessages"
    KEY_NAME = "messageId"
    MODEL = ReplyMessage

    _db.execAndCommit("""
        CREATE TABLE IF NOT EXISTS replyRootMessages (
            messageId BLOB PRIMARY KEY,
            publicKey BLOB NOT NULL,
            content TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            signed BLOB NOT NULL
        )
    """)