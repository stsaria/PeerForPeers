from enum import IntEnum

class AppElementSize:
    APP_FLAG = 1
    MODE_FLAG = 1

class GlobalAppElementSize(AppElementSize):
    TIMESTAMP = 8
    ED25519_PUBLIC_KEY = 32
    ED25519_SIGN = 64
    MESSAGE_ID = 16
    NODES_LIMIT_FOR_GET = 2
    MESSAGES_LIMIT_FOR_GET = 2
    IP_STR = 19
    PORT = 2
    MESSAGE_TYPE = 1
    MESSAGE_SIZE = 2 # message content length's bytes size

class IAmInfoElementSize:
    MAJOR = 100

class MessageType(IntEnum):
    MESSAGE = 1
    REPLY_MESSAGE = 2

class AppFlag(IntEnum):
    GLOBAL = 1
    DIRECT = 2

class AppModeFlag(IntEnum):
    HELLO = 1
    RESP_HELLO = 2

    GET_NODES = 10
    RESP_GET_NODES = 11
    START_SEND_REQ = 12
    GET_MESSAGES = 13
    RESP_GET_MESSAGES = 14
    GET_OTHERS_MESSAGE = 15
    RESP_GET_OTHER_MESSAGE = 16


