from dataclasses import dataclass

@dataclass(kw_only=True)
class NetConfig:
    addrV4:tuple[str, int] | None
    addrV6:tuple[str, int] | None