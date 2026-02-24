from src.protocol.Protocol import *
from src.app.protocol.Protocol import *

# This file is editable for custom configurations

MESSAGES_FILE = "messages.dat"
FRIENDS_PUBKEYS_FILE = "friendPubKeys.dat"

GET_I_AM_FUNC_NAME = "getIAm"
GET_SORTED_NODES_FUNC_NAME = "getSortedNodes"
GET_SORTED_RELAY_ROUTES_FUNC_NAME = "getSortedRelayRoutes"

MAX_FIRENDS = 30 # change for friend nodes
MAX_NODES = 100-MAX_FIRENDS
MAX_NODES_MARGIN = 20

NODES_LIMIT_FOR_GET = 9

MESSAGE_CONTENT_LIMIT = (
    SOCKET_BUFFER
    - SecurePacketElementSize.MAGIC
    - SecurePacketElementSize.PACKET_FLAG
    - SecurePacketElementSize.MODE_FLAG
    - (((
        GlobalAppElementSize.APP_FLAG
        + GlobalAppElementSize.MODE_FLAG
        + GlobalAppElementSize.MESSAGE_ID
        + GlobalAppElementSize.TIMESTAMP
        + GlobalAppElementSize.ED25519_PUBLIC_KEY
        + GlobalAppElementSize.ED25519_SIGN
    )//16)*16) # aes padding alignment
) # other's message content size limit = 894 bytes
MESSAGE_LIST_LIMIT = 100
MESSAGES_LIMIT_FOR_GET = 5

MESSAGE_LIFE_SEC = 60*60*24

CHANCE_FOR_SEND_REPLY_MESSAGE = 1/5

class StatusForHelloForApp(StatusForHello):
    UNKNOWN = -1

class SyncIntervalSec:
    GLOBAL = 60
    DIRECT = 15

class PingIntervalSec:
    DIRECT = 5



DIRECT_VOICE_SAMPLING_RATE = 16000
DIRECT_VOICE_CHANNELS = 1
DIRECT_VOICE_SAMPLE_SEC = 0.02
# Opus encoded size (maybe 150~300b) < getMaxDataSizeOnAesEncrypted()
DIRECT_VOICE_DEVICE_DEFAULT = -1
DIRECT_VOICE_NOT_SPEAKING_BYTES_THRESHOLD = 20  # adjust based on microphone sensitivity