from src.protocol.Protocol import *
from src.app.protocol.Protocol import *

# This file is editable for custom configurations

DB_FILE = "P4P.db"

GET_I_AM_FUNC_NAME = "getIAm"
GET_SORTED_NODES_FUNC_NAME = "getSortedNodes"

MAX_NODES = 100
MAX_NODES_MARGIN = 15

NODES_LIMIT_FOR_GET = 9

MESSAGE_CONTENT_LIMIT = (
    SOCKET_BUFFER
    - SecurePacketElementSize.MAGIC
    - SecurePacketElementSize.PACKET_FLAG
    - SecurePacketElementSize.MODE_FLAG
    - ((
        GlobalAppElementSize.APP_FLAG
        - GlobalAppElementSize.MODE_FLAG
        - GlobalAppElementSize.MESSAGE_ID
        - GlobalAppElementSize.TIMESTAMP
        - GlobalAppElementSize.ED25519_PUBLIC_KEY
        - GlobalAppElementSize.ED25519_SIGN
    )//16)*16 # aes padding alignment
) # other's message content size limit = 894 bytes
MESSAGE_LIST_LIMIT = 100
MESSAGES_LIMIT_FOR_GET = 5

MESSAGE_LIFE_SEC = 60*60*24

CHANCE_FOR_SEND_REPLY_MESSAGE = 1/5