from enum import IntEnum

DIRECT_APP_MAX_NODES = 4

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
    IP = 19
    PORT = 2
    MESSAGE_TYPE = 1
    MESSAGE_SIZE = 2 # message content length's bytes size
    NODES_SIZE = 2

class IAmInfoElementSize:
    IP = 19
    PORT = 2
    MAJOR = 100

class MessageType(IntEnum):
    MESSAGE = 1
    REPLY_MESSAGE = 2

class DirectAppElementSize(AppElementSize):
    STATUS_FOR_HELLO = 1
    NODES_SIZE = 2
    RELAY_ROUTE_TYPE = 1
    VOICE_SAMPLING_RATE = 2
    VOICE_CHANNELS = 1
    VOICE_SAMPLE_MILLI_SEC = 1

class StatusForHello(IntEnum):
    SUCCESS = 0
    OVER_MAX_NODES = 1
    CANNOT_CONNECT_BY_OTHER_NODE = 2

class AppFlag(IntEnum):
    GLOBAL = 1
    DIRECT = 2

class AppModeFlag(IntEnum):
    HELLO = 1
    RESP_HELLO = 2
    GET_NODES = 3

    RESP_GET_NODES = 10
    START_SEND_REQ = 11
    GET_MESSAGES = 12
    RESP_GET_MESSAGES = 13
    GET_OTHERS_MESSAGE = 14
    RESP_GET_OTHER_MESSAGE = 15
    REQ_FRIEND = 16
    RESP_FRIEND = 17
    SECOND_RESP_FRIEND = 18
    AM_I_FRIEND = 19
    RESP_AM_I_FRIEND = 20
    INVITE_FOR_DIRECT_APP = 21

    INFORM_NEW_NODE = 30
    SEND_NODES_LIST = 31
    ACTIVATE_RELAY_ROUTE = 32
    MAIN_DATA_RELAY_ROUTE = 33
    STOP_ACTIVATE_RELAY_ROUTE = 34

class DirectAppReleyRouteType(IntEnum):
    # Warn: if recved an activate route packet and you dont know the route type,
    # don't use the data itself but but KEEP ON RUNNING ONLY RELAY.(absol dont break the relay route)
    UNKNOWN = -1
    VOICE = 1
    CUSTOM = 3

class DirectAppInviteType(IntEnum):
    NEW = 1
    REPEAT = 2

DIRECT_VOICE_DATA_TYPE = "int16"

