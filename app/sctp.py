"""SCTP 报文解析：公共头 + DATA / FORWARD-TSN 块。

仅解释公共头、DATA 块与 FORWARD-TSN 块；其余块类型保留为不透明块，
由审计引擎决定忽略。校验和为 CRC-32C，字段按小端存放（RFC 4960）。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from .crc32c import crc32c

CHUNK_DATA = 0
CHUNK_FORWARD_TSN = 192

COMMON_HEADER_LEN = 12
MAX_PACKET_SIZE = 65535

FLAG_END = 0x01
FLAG_BEGIN = 0x02
FLAG_UNORDERED = 0x04


class SctpError(Exception):
    """报文结构非法。"""


class ChecksumError(SctpError):
    """CRC32C 校验失败。"""

    def __init__(self, expected: int, computed: int):
        super().__init__(f"CRC32C 不匹配: 字段=0x{expected:08x} 计算=0x{computed:08x}")
        self.expected = expected
        self.computed = computed


@dataclass
class DataChunk:
    raw: bytes          # 块原始字节（不含尾部填充）
    tsn: int
    stream: int
    ssn: int
    ppid: int
    payload: bytes
    unordered: bool
    begin: bool
    end: bool
    type_name = "DATA"


@dataclass
class ForwardTsnChunk:
    raw: bytes
    new_cum_tsn: int
    pairs: list         # list[tuple[int, int]] = (stream, ssn)
    type_name = "FORWARD-TSN"


@dataclass
class OpaqueChunk:
    raw: bytes
    ctype: int
    type_name = "CHUNK"


@dataclass
class ParsedPacket:
    source_port: int
    dest_port: int
    verification_tag: int
    chunks: list


def parse_packet(raw: bytes) -> ParsedPacket:
    """解析并校验一个 SCTP 报文；结构或校验和非法时抛出 SctpError。"""
    if len(raw) < COMMON_HEADER_LEN:
        raise SctpError(f"报文过短: {len(raw)} 字节 < 公共头 {COMMON_HEADER_LEN} 字节")
    if len(raw) > MAX_PACKET_SIZE:
        raise SctpError(f"报文过长: {len(raw)} 字节")

    source_port, dest_port, vtag = struct.unpack(">HHI", raw[:8])
    (expected_crc,) = struct.unpack("<I", raw[8:12])
    computed = crc32c(raw[:8] + b"\x00\x00\x00\x00" + raw[12:])
    if computed != expected_crc:
        raise ChecksumError(expected_crc, computed)

    chunks = []
    offset = COMMON_HEADER_LEN
    while offset < len(raw):
        if len(raw) - offset < 4:
            raise SctpError("尾部残留字节不足以构成块头")
        ctype, _flags, clen = struct.unpack(">BBH", raw[offset:offset + 4])
        if clen < 4:
            raise SctpError(f"块长度非法: {clen}")
        if offset + clen > len(raw):
            raise SctpError("块长度超出报文边界")
        chunk_raw = raw[offset:offset + clen]
        chunks.append(_parse_chunk(ctype, chunk_raw))
        offset += (clen + 3) & ~3  # 块按 4 字节对齐填充

    return ParsedPacket(source_port, dest_port, vtag, chunks)


def _parse_chunk(ctype: int, raw: bytes):
    flags = raw[1]
    if ctype == CHUNK_DATA:
        if len(raw) < 17:  # 16 字节块头 + 至少 1 字节用户数据
            raise SctpError("DATA 块过短")
        tsn, stream, ssn, ppid = struct.unpack(">IHHI", raw[4:16])
        return DataChunk(
            raw=raw, tsn=tsn, stream=stream, ssn=ssn, ppid=ppid,
            payload=raw[16:],
            unordered=bool(flags & FLAG_UNORDERED),
            begin=bool(flags & FLAG_BEGIN),
            end=bool(flags & FLAG_END),
        )
    if ctype == CHUNK_FORWARD_TSN:
        if len(raw) < 8 or (len(raw) - 8) % 4 != 0:
            raise SctpError("FORWARD-TSN 块结构非法")
        (new_cum,) = struct.unpack(">I", raw[4:8])
        pairs = [struct.unpack(">HH", raw[i:i + 4]) for i in range(8, len(raw), 4)]
        return ForwardTsnChunk(raw=raw, new_cum_tsn=new_cum, pairs=pairs)
    return OpaqueChunk(raw=raw, ctype=ctype)
