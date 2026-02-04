from enum import IntEnum

def itob(i:int | IntEnum, size:int, endian:str, signed=False) -> bytes:
    return (i.value if isinstance(i, IntEnum) else i).to_bytes(size, endian, signed=signed)

def btoi(bI:bytes, endian:str, signed=False) -> int:
    return int.from_bytes(bI, endian, signed=signed)

def stob(s:str, size:int, encoding:str) -> bytes:
    b = bytearray()
    for c in s:
        if size and len(b) + len(c.encode(encoding)) > size:
            break
        b += c.encode(encoding, errors="ignore")
    return bytes(b)

def btos(b:bytes, encoding:str) -> str:
    return b.rstrip(b"\x00").decode(encoding, errors="ignore")