from enum import IntEnum
from uuid import UUID

from P4PCore.protocol.Protocol import PacketElementSize

DEFAULT_PLUGIN_BASE_UUID4S = {
    "NodeGossiper": UUID("433e6f6246674db0b897385b0644be18"),
    "PluginIdentifiesLister": UUID("cd90b976606147ed83920420234271c1")
}

class SimplePluginElementSize(PacketElementSize):
    MODE_FLAG = 1

class NodeGossiperPacketElementSize(SimplePluginElementSize):
    IP_ADDR_FAMILY_BYTES = 1
    IPV4_BYTES = 4
    IPV6_BYTES = 16
    IP_BYTES = 16
    PORT_BYTES = 2
    ED25519_PUBLIC_KEY_BYTES = 32

class PluginsListerModeFlag(IntEnum):
    GET_LIST = 1
    RESP_GET_LIST = 2

class PluginsListerPacketElementSize(SimplePluginElementSize):
    PLUGIN_UUID = 16