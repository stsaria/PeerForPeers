
from dataclasses import dataclass
from uuid import UUID

from P4PCore.model.NodeIdentify import NodeIdentify

@dataclass
class Node:
    nodeIdentify:NodeIdentify
    pluginUuids:list[UUID]