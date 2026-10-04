"""测试与冒烟共用的 SCTP 报文构造工具。"""
from __future__ import annotations

import base64
import struct

from app.crc32c import crc32c

DATA = 0
FORWARD_TSN = 192
HEARTBEAT = 4


def data_chunk(tsn: int, ssn: int, payload, stream: int = 0,
               begin: bool = True, end: bool = True,
               unordered: bool = False, ppid: int = 0) -> bytes:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    flags = ((0x04 if unordered else 0)
             | (0x02 if begin else 0)
             | (0x01 if end else 0))
    length = 16 + len(payload)
    chunk = struct.pack(">BBHIHHI", DATA, flags, length,
                        tsn, stream, ssn, ppid) + payload
    return chunk + b"\x00" * ((-len(chunk)) % 4)


def forward_tsn_chunk(new_cum: int, pairs=()) -> bytes:
    body = struct.pack(">I", new_cum)
    for stream, ssn in pairs:
        body += struct.pack(">HH", stream, ssn)
    chunk = struct.pack(">BBH", FORWARD_TSN, 0, 4 + len(body)) + body
    return chunk + b"\x00" * ((-len(chunk)) % 4)


def heartbeat_chunk() -> bytes:
    return struct.pack(">BBH", HEARTBEAT, 0, 4)


def packet(chunks, sport: int = 5000, dport: int = 5000,
           vtag: int = 0x01020304) -> bytes:
    body = b"".join(chunks)
    header = struct.pack(">HHI", sport, dport, vtag) + b"\x00\x00\x00\x00"
    crc = crc32c(header + body)
    return header[:8] + struct.pack("<I", crc) + body


def corrupt_checksum(pkt: bytes) -> bytes:
    """翻转校验和字段的一个字节，使 CRC32C 校验失败。"""
    return pkt[:8] + bytes([pkt[8] ^ 0xFF]) + pkt[9:]


def b64(pkt: bytes) -> str:
    return base64.b64encode(pkt).decode("ascii")
