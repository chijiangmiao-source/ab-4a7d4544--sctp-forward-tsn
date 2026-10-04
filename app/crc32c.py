"""CRC-32C (Castagnoli)，SCTP 校验和算法（RFC 4960 附录 B）。

反射多项式 0x82F63B78（原多项式 0x1EDC6F41），初值/终值异或 0xFFFFFFFF。
SCTP 报文中校验和字段按小端存放。
"""
from __future__ import annotations

_POLY = 0x82F63B78


def _build_table() -> list[int]:
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ _POLY if crc & 1 else crc >> 1
        table.append(crc)
    return table


_TABLE = _build_table()


def crc32c(data: bytes, crc: int = 0) -> int:
    """计算 CRC-32C；传入前一次返回值可增量计算。"""
    crc ^= 0xFFFFFFFF
    for byte in data:
        crc = _TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF
