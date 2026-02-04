from enum import IntEnum

ENDIAN = "big"

MAGIC = b"P4P"

PROTOCOL_CLIENT = 1.0

PROTOCOL_VER = 1

MAGIC += bytes([PROTOCOL_CLIENT, PROTOCOL_VER])

SOCKET_BUFFER = 1024
STR_ENCODING = "utf-8"

REDUNDANCY = 3

RELIABLE_PACKETS_PER_CHUNK = 30
"""
    RELIABLE_PACKETS_PER_CHUNK <= (
        SOCKET_BUFFER
        -ReliablePacketElementSize.PACKET_FLAG
        -ReliablePacketElementSize.PACKET_MODE_FLAG
        -ReliablePacketElementSize.SESSION_ID
        -ReliablePacketElementSize.ED25519_SIGN
    ) // ReliablePacketElementSize.SEQ_AND_CHUNK_COUNT
"""

ANY_SESSION_ID_SIZE = 16

AES_NONCE_SIZE = 12

RELIABLE_SESSION_ID_SIZE = 2

ANY_SECRET_SIZE = 32

class X25519DeriveInfoBase:
    SECURE = "SECURE_X25519_DERIVE_KEY"
    RELIABLE = "RELIABLE_X25519_DERIVE_KEY"

class X25519AndAesKeyInfoBase:
    SECURE = "ENCRYPTED_X25519-AESGCM_KEY"
    RELIABLE = "SPLIT_AND_ENCRYPTED_X25519-AESGCM_KEY"

class AesKeyInfoBase:
    PRIVATE_SECURE = "PRIVATE_SECURE_AESGCM_KEY,{0}"

class PacketElementSize:
    MAGIC = len(MAGIC)
    PACKET_FLAG=1
    MODE_FLAG=1

class SecurePacketElementSize(PacketElementSize):
    USER_NAME=64
    PROTOCOL_CLIENT=2
    PROTOCOL_VER=4
    ED25519_PUBLIC_KEY=32
    ED25519_SIGN=64
    X25519_PUBLIC_KEY=32
    AES_SALT=32
    SEQ=8
    
    IP = 19
    PORT = 2

    IS_SUCCESS_AGENCY_PING = 1

class ReliablePacketElementSize(PacketElementSize):
    SESSION_ID=2
    OPERATOR=1
    HASH256=32
    X25519_PUBLIC_KEY=32
    ED25519_SIGN=64
    AES_SALT=32
    SEQ_AND_CHUNK_COUNT=8
    REDUNDANCY_COUNT=AES_NONCE_SIZE-SEQ_AND_CHUNK_COUNT # 4

class PrivateSecurePacketElementSize(PacketElementSize):
    ED25519_PUBLIC_KEY=32
    ED25519_SIGN=64
    AES_SALT=32
    SEQ=8

class GossipPacketElementSize(PacketElementSize):
    XXHASH64=8
    IP = 19
    PORT = 2
    ED25519_PUBLIC_KEY=32

class PacketFlag(IntEnum):
    PLAIN = 1
    SECURE = 2
    RELIABLE = 3
    PRIVATE_SECURE = 4
    GOSSIP = 5

class PacketModeFlag(IntEnum):
    PING = 1
    PONG = 2
    HELLO = 3
    RESP_HELLO = 4
    SECOND_HELLO = 5
    MAIN_DATA = 6

    AGENCY_PING = 10
    RESP_AGENCY_PING = 11

    CHUNK_CHECK = 20
    RESP_CHUNK_CHECK = 21
    REDUNDANCY = 22

    GOSSIP = 30

class CommuType(IntEnum):
    GET_MESSAGE_LIST = 1
    RESP_GET_MESSAGE_LIST = 2
    GET_NODE_LIST = 3
    RESP_GET_NODE_LIST = 4
    GET_MY_IP_AND_PORT = 5
    RESP_GET_MY_IP_AND_PORT = 6
    INVITE_TO_DIRECT_NET = 7

    SEND_MESSAGE = 10
    SEND_VOICE = 11