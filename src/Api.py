from threading import Event, Lock
from typing import Generator
from enum import auto as a

from app.GlobalApp import GlobalApp as GApp
from app.model.Node import Relay
from src.app.DirectApp import DirectApp as DApp

from app.model.Message import MyMessage, MyReplyMessage, OthersMessage
from app.protocol.ProgramProtocol import StatusForHelloForApp
from model.NodeIdentify import NodeIdentify
from src.model.NetConfig import SecureNetConfig
from util import ed25519
from util.Result import Result
from util.ed25519 import Ed25519PrivateKey

class _DApi:
    _directApp:DApp = None
    _networkEd25519PrivateKey:Ed25519PrivateKey = None
    _sharedSecret:bytes = None
    _secretsLock:Lock = None

    @classmethod
    def init(cls, ed25519PublicKeyBytes:bytes, port:int, ipv4:str, ipv6:str):
        """
        Initialize global node.
        Warn: All other functions will not work before calling this function.
        """
        ed25519PubKey = ed25519.getPubKeyByPubKeyBytes(ed25519PublicKeyBytes)
        cls._globalApp = DApp(
            SecureNetConfig(
                addrV4=[ipv4, port],
                addrV6=[ipv6, port],
                ed25519PrivateKey=ed25519PubKey
            )
        )
        cls._networkEd25519PrivateKey:Ed25519PrivateKey = None
        cls._sharedSecret:bytes = None
        cls._secretsLock:Lock = Lock()
    
    @classmethod
    def clear(cls) -> None:
        """
        Clear direct app.
        Warn: Basically, only call this function to end program.
        """
        cls._networkEd25519PrivateKey = None
        cls._sharedSecret = None

    @classmethod
    def createNetwork(cls) -> bool:
        """
        Create new network.
        Return True if success, False if failed.
        """
        nwI = cls._directApp.createNetwork()
        if DApp.CreateNetworkResult.SUCCESS != nwI:
            return False
        cls._networkEd25519PrivateKey, cls._sharedSecret = nwI
        return True

    InviteNodeToDirectResult = DApp.InviteForDirectAppResult
    @classmethod
    def inviteNodeToDirect(cls, nodeIdentify:NodeIdentify) -> InviteNodeToDirectResult:
        """
        Invite node to network.
        Return True if success, False if failed.
        """
        return cls._directApp.inviteForDirectApp(
            nodeIdentify,
            cls._networkEd25519PrivateKey,
            cls._sharedSecret
        )

    
    __ActivateInviteResult = DApp.JoinNetworkResult
    @classmethod
    def __activateInvite(cls, bootstrapNodeIdentify:NodeIdentify, sharedEd25519PrivateKeyBytes:bytes, sharedSecret:bytes) -> __ActivateInviteResult:
        """
        Join network via bootstrap node.
        Return status for join network.
        If failed, return None.
        """
        if (r := cls._directApp.joinNetwork(
            bootstrapNodeIdentify,
            pK := ed25519.getPivKeyByPivKeyBytes(sharedEd25519PrivateKeyBytes),
            sS := sharedSecret
        )) == DApp.JoinNetworkResult.SUCCESS:
            with cls._secretsLock:
                cls._networkEd25519PrivateKey = pK
                cls._sharedSecret = sS
        return r

    @classmethod
    def keepSendingVoice(cls, stop:Event) -> Generator[bool, None, None]:
        """
        Send voice data to friends.
        Yield am i speaking now every DIRECT_VOICE_SAMPLE_SEC seconds.
        """
        return cls._directApp.keepSendingVoice(stop)
    
    @classmethod
    def keepGettingActivatedVoiceRoute(cls, stop:Event) -> Generator[tuple[bool, bytes, Relay], None, None]:
        """
        Keep Getting activated voice relay route.

        """
        return cls._directApp.keepGettingActivatedVoiceRoute(stop)
    
    @classmethod
    def listenByRoute(cls, routeId:bytes) -> Generator[bytes, None, None] | None:
        """
        Listen by relay route.
        Return generator of voice data if success, None if failed.
        """
        return cls._directApp.listenByRoute(routeId)
    
    @classmethod
    def stopListenByRoute(cls, routeId:bytes) -> None:
        """
        Stop listen by relay route.
        """
        cls._directApp.stopListenByRoute(routeId)

class _GApi:
    _globalApp:GApp = None
    _invitedNodeAndSecrets:dict[NodeIdentify, tuple[bytes, bytes]] = None
    _invitedNodeAndSecretsLock:Lock = None

    @classmethod
    def init(cls, ed25519PublicKeyBytes:bytes, port:int, ipv4:str, ipv6:str):
        """
        Initialize global node.
        Warn: All other functions will not work before calling this function.
        """
        ed25519PubKey = ed25519.getPubKeyByPubKeyBytes(ed25519PublicKeyBytes)
        cls._globalApp = GApp(
            SecureNetConfig(
                addrV4=[ipv4, port],
                addrV6=[ipv6, port],
                ed25519PrivateKey=ed25519PubKey
            )
        )
        cls._invitedNodeAndSecrets = {}
        cls._invitedNodeAndSecretsLock = Lock()
    
    @classmethod
    def clear(cls) -> None:
        """
        Clear global app.
        Warn: Basically, only call this function to end program.
        """
        cls._globalApp.stop()
        with cls._invitedNodeAndSecretsLock:
            cls._invitedNodeAndSecrets = None
        cls._globalApp = None
    
    @classmethod
    def start(cls) -> None:
        """
        Start global node.
        Warn: Most other functions before call this function will not work.
        """
        cls._globalApp.start()

    @classmethod
    def setIgnoreReqFriends(cls, ignore:bool) -> None:
        """
        Set boolean of ignore request friends.
        """
        cls._globalApp.setIgnoreReqFriends(ignore)
    
    @classmethod
    def getIgnoreReqFriends(cls) -> bool:
        """
        Get boolean of ignore request friends.
        """
        return cls._globalApp.getIgnoreReqFriends()
    
    AddNodeResult = GApp.AcceptReqResult
    @classmethod
    def addNode(cls, nodeIdentify:NodeIdentify) -> AddNodeResult:
        """
        Add node to global node.
        """
        return cls._globalApp._hello(nodeIdentify)

    @classmethod
    def getNodes(cls) -> list[NodeIdentify]:
        """
        Get nodes of global node.
        """
        return cls._globalApp.getNodes()
    
    @classmethod
    def keepGettingNodes(cls) -> Generator[NodeIdentify, None, None]:
        """
        Keep getting nodes of global node.
        """
        return cls._globalApp.keepGettingNodes()
    
    AddFriendNodeResult = GApp.AddFriendResult
    @classmethod
    def addFriendNode(cls, nodeIdentify:NodeIdentify) -> AddFriendNodeResult:
        """
        Add friend node to global node.
        Warn: Must add node first.
        """
        return cls._globalApp.addFriend(nodeIdentify)

    @classmethod
    def getFriends(cls) -> list[NodeIdentify]:
        """
        Get friends of global node.
        """
        return list(cls._globalApp.getFriends())
    
    @classmethod
    def keepGettingFriends(cls, stop:Event) -> Generator[list[NodeIdentify], None, None]:
        """
        Keep getting friends of global node.
        """
        return cls._globalApp.keepGettingFriends(stop)

    @classmethod
    def getOnlineFriends(cls) -> list[NodeIdentify]:
        """
        Get online friends of global node.
        """
        return cls._globalApp.getOnlineFriends()
    
    @classmethod
    def keepGettingOnlineFriends(cls, stop:Event) -> Generator[list[NodeIdentify], None, None]:
        """
        Keep getting online friends of global node.
        """
        return cls._globalApp.keepGettingOnlineFriends(stop)
    
    @classmethod
    def getWaitingToAddFriends(cls) -> list[NodeIdentify]:
        """
        Get waiting friends of global node.
        """
        return list(cls._globalApp.getWaitingToAddFriends())
    
    @classmethod
    def keepGettingWaitingToAddFriends(cls, stop:Event) -> Generator[list[NodeIdentify], None, None]:
        """
        Keep getting waiting friends of global node.
        """
        return cls._globalApp.keepGettingWaitingToAddFriends(stop)
    
    @classmethod
    def getRequestedToMeFriends(cls) -> list[NodeIdentify]:
        """
        Get request friends of global node.
        """
        return list(cls._globalApp.getRequestedToMeFriends())
    
    @classmethod
    def keepGettingRequestedToMeFriends(cls, stop:Event) -> Generator[list[NodeIdentify], None, None]:
        """
        Keep getting request friends of global node.
        """
        return cls._globalApp.keepGettingRequestedToMeFriends(stop)
    
    AcceptReqFriendResult = GApp.AcceptReqResult
    @classmethod
    def acceptReqFriend(cls, nodeIdentify:NodeIdentify) -> AcceptReqFriendResult:
        """
        Accept request friend of global node.
        """
        return cls._globalApp.acceptReqFriend(nodeIdentify)
    
    @classmethod
    def checkAmIFriend(cls, nodeIdentify:NodeIdentify) -> bool:
        """
        Check if node is friend of global node.
        """
        return cls._globalApp.checkAmIFriend(nodeIdentify)

    @classmethod
    def removeFriend(cls, nodeIdentify:NodeIdentify) -> None:
        """
        Remove friend of global node.
        """
        cls._globalApp.removeFriend(nodeIdentify)
    
    PostMessageResult = GApp.PostMessageResult
    @classmethod
    def postMessage(cls, message:str) -> None:
        """
        Post message to global node.
        maximum number of characters is src.app.GlobalApp.MAX_MESSAGE_SIZE
        """
        cls._globalApp.postMessage(message)
    
    PostReplyMessageResult = GApp.PostReplyMessageResult
    @classmethod
    def postReplyMessage(cls, messageId:bytes, message:str) -> None:
        """
        Post reply message to global node.
        maximum number of characters is src.app.GlobalApp.MAX_MESSAGE_SIZE
        """
        cls._globalApp.postReplyMessage(messageId, message)

    @classmethod
    def getMyMessages(cls) -> list[MyMessage]:
        """
        Get my messages of global node.
        Warn: This function will not return reply messages.
        """
        return list(cls._globalApp.getMyMessages())
    
    @classmethod
    def getMyReplyMessages(cls) -> list[MyReplyMessage]:
        """
        Get my reply messages of global node.
        """
        return list(cls._globalApp.getMyReplyMessages())
    
    @classmethod
    def getMessages(cls, onlyOthers:bool=False) -> dict[OthersMessage, list[OthersMessage]]:
        """
        Get messages of global node.
        Return the message and its reply.
        Not duplicate.

        If onlyOthers is True, only return other people's messages.
        """
        return list(cls._globalApp.getMessages(onlyOthers=onlyOthers))

    @classmethod    
    def getInviteForDirectApp(cls) -> list[NodeIdentify]:
        """
        Get invite for direct app of global node.
        Return list of tuple of (bootstrap node identify, shared ed25519 private key bytes, shared secret).
        """
        ns = []

        for nodeIdentify, (sharedEd25519PrivateKeyBytes, sharedSecret) in cls._globalApp.getInvitedNodeAddrAndSecrets().items():
            with cls._invitedNodeAndSecretsLock:
                cls._invitedNodeAndSecrets[nodeIdentify] = (sharedEd25519PrivateKeyBytes, sharedSecret)
            ns.append(nodeIdentify)
        return ns
    
    @classmethod
    def keepGettingInviteForDirectApp(cls, stop:Event) -> Generator[list[NodeIdentify], None, None]:
        """
        Keep getting invite for direct app of global node.
        Return list of tuple of (bootstrap node identify, shared ed25519 private key bytes, shared secret).
        """
        for invitedNodeAddrAndSecrets in cls._globalApp.keepGettingInvitedNodeAddrAndSecrets(stop):
            ns = []
            for nodeIdentify, (sharedEd25519PrivateKeyBytes, sharedSecret) in invitedNodeAddrAndSecrets.items():
                with cls._invitedNodeAndSecretsLock:
                    cls._invitedNodeAndSecrets[nodeIdentify] = (sharedEd25519PrivateKeyBytes, sharedSecret)
                ns.append(nodeIdentify)
            yield ns

    
    class ActivateInviteNodeToDirectResult(_DApi.__ActivateInviteResult):
        NODE_IS_NOT_IN_INVITED_LIST = a()
    @classmethod
    def activateInviteForDirectApp(cls, bootstrapNodeIdentify:NodeIdentify) -> ActivateInviteNodeToDirectResult:
        """
        Activate invite for direct app of global node.
        Return True if success, False if failed.
        """
        with cls._invitedNodeAndSecretsLock:
            if bootstrapNodeIdentify not in cls._invitedNodeAndSecrets:
                return cls.ActivateInviteNodeToDirectResult.NODE_IS_NOT_IN_INVITED_LIST
            sharedEd25519PrivateKeyBytes, sharedSecret = cls._invitedNodeAndSecrets[bootstrapNodeIdentify]
        return cls.ActivateInviteNodeToDirectResult(_DApi.__activateInvite(bootstrapNodeIdentify, sharedEd25519PrivateKeyBytes, sharedSecret).value)

class Api:
    globalApp:_GApi = None
    directApp:_DApi = None

    @classmethod
    def init(cls, ed25519PublicKeyBytes:bytes, port:int, ipv4:str, ipv6:str):
        """
        Initialize global node and direct node.
        Warn: All other functions will not work before calling this function.
        """
        cls.globalApp = _GApi()
        cls.globalApp.init(ed25519PublicKeyBytes, port, ipv4, ipv6)
        cls.directApp = _DApi()
        cls.directApp.init(ed25519PublicKeyBytes, port, ipv4, ipv6)
    
    @classmethod
    def clear(cls) -> None:
        """
        Clear global node and direct node.
        Warn: Basically, only call this function to end program.
        """
        cls.globalApp.clear()
        cls.directApp.clear()