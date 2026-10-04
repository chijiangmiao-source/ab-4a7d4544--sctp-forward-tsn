"""单关联、单有序流的 SCTP 逐包审计引擎。

语义约定
--------
* 仅审查 DATA 与 FORWARD-TSN 块，其余块类型记为 ignored。
* 每个报文恰好得到一条冻结裁决：accepted / duplicate / stale / ignored / rejected。
* 裁决一旦生成即不可变；同一审计标识重读时必须逐字节一致。
* 字节完全相同的 DATA 重传 => duplicate，不增加消息数。
* 同一 TSN 字节不同 => rejected(tsn-conflict)，并记录首个原始字节依据。
* 非法流序（错流、错 SSN、重复 B/E、乱序标志 U=1）=> rejected。
* 越界跳过（FORWARD-TSN 未推进累计 TSN，或无 TSN 基线）=> rejected。
* 被合法 FORWARD-TSN 跨越的缺失片段不交付残缺消息；事后补交旧片段 => stale，
  不改变既有结论。
* TSN 按不回绕的 32 位序号处理（弱链路捕获窗口 ≤32 包，假设不跨回绕点）。
"""
from __future__ import annotations

import base64

from .sctp import (
    ChecksumError,
    DataChunk,
    ForwardTsnChunk,
    SctpError,
    parse_packet,
)

MAX_PACKETS = 32
EVIDENCE_BYTES = 16

# 裁决类型
ACCEPTED = "accepted"
DUPLICATE = "duplicate"
STALE = "stale"
IGNORED = "ignored"
REJECTED = "rejected"

# 冻结拒绝原因
R_BAD_CHECKSUM = "bad-checksum"
R_MALFORMED = "malformed-packet"
R_TSN_CONFLICT = "tsn-conflict"
R_ILLEGAL_STREAM = "illegal-stream"
R_ILLEGAL_ORDER = "illegal-stream-order"
R_UNORDERED = "unordered-data"
R_SKIP_BOUNDS = "skip-out-of-bounds"
R_SKIP_MISSING = "skip-missing-stream-entry"


class AuditEngine:
    """按捕获顺序处理报文，维护累计 TSN / 缓存分片 / 跳过范围 / 已交付消息。"""

    def __init__(self) -> None:
        self.stream_id: int | None = None      # 首个被接受的 DATA 绑定审查流
        self.expected_ssn: int | None = None   # 下一个应交付的流序号
        self.received: dict[int, bytes] = {}   # tsn -> DATA 块原始字节
        self.received_at: dict[int, int] = {}  # tsn -> 首次出现的报文序号
        self.forward_floor: int | None = None  # 已被 FORWARD-TSN 推进到的下界
        self.skipped_tsns: set[int] = set()    # 被跨越且从未收到的 TSN
        self.skipped_ranges: list[list[int]] = []
        self.skipped_ssns: set[int] = set()    # 被 FORWARD-TSN 宣告放弃的消息
        self.buffer: dict[int, dict[int, dict]] = {}  # ssn -> {tsn: 分片}
        self.delivered: list[dict] = []
        self.delivered_ssns: set[int] = set()
        self.verdicts: list[dict] = []

    # ------------------------------------------------------------------ API

    def process(self, packets: list[bytes]) -> None:
        for index, raw in enumerate(packets):
            self.verdicts.append(self._process_packet(index, raw))

    def result(self) -> dict:
        return {
            "verdicts": self.verdicts,
            "messages": self.delivered,
            "final_state": self._state_snapshot(),
        }

    # ------------------------------------------------------------- 内部状态

    def _cum_tsn(self) -> int | None:
        """累计 TSN：自最小已知 TSN 起连续覆盖（收到或被跳过）的最大值。"""
        known = set(self.received) | self.skipped_tsns
        if not known:
            return None
        cum = min(known) - 1
        while cum + 1 in known:
            cum += 1
        return cum

    def _state_snapshot(self) -> dict:
        return {
            "cum_tsn": self._cum_tsn(),
            "stream_id": self.stream_id,
            "expected_ssn": self.expected_ssn,
            "buffered": [
                {
                    "ssn": ssn,
                    "fragments": [
                        {
                            "tsn": tsn,
                            "begin": frag["begin"],
                            "end": frag["end"],
                            "length": frag["length"],
                        }
                        for tsn, frag in sorted(frags.items())
                    ],
                }
                for ssn, frags in sorted(self.buffer.items())
            ],
            "skipped_ranges": [list(r) for r in self.skipped_ranges],
            "skipped_ssns": sorted(self.skipped_ssns),
            "delivered_count": len(self.delivered),
        }

    @staticmethod
    def _runs(tsns: list[int]):
        """把已排序的被跨越 TSN 列表切成连续段（已收到的 TSN 不算跳过）。"""
        if not tsns:
            return
        start = prev = tsns[0]
        for tsn in tsns[1:]:
            if tsn != prev + 1:
                yield start, prev
                start = tsn
            prev = tsn
        yield start, prev

    def _merge_range(self, start: int, end: int) -> None:
        self.skipped_ranges.append([start, end])
        self.skipped_ranges.sort()
        merged = [self.skipped_ranges[0]]
        for lo, hi in self.skipped_ranges[1:]:
            if lo <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        self.skipped_ranges = merged

    # ------------------------------------------------------------- 逐包处理

    def _process_packet(self, index: int, raw: bytes) -> dict:
        verdict = {
            "index": index,
            "verdict": None,
            "reason": None,
            "chunks": [],
            "evidence": None,
        }
        try:
            packet = parse_packet(raw)
        except ChecksumError as exc:
            verdict.update(verdict=REJECTED, reason=R_BAD_CHECKSUM)
            verdict["evidence"] = {
                "offending_first_bytes_hex": raw[:EVIDENCE_BYTES].hex(),
                "expected_crc32c": f"0x{exc.expected:08x}",
                "computed_crc32c": f"0x{exc.computed:08x}",
            }
            return self._finish(verdict)
        except SctpError as exc:
            verdict.update(verdict=REJECTED, reason=R_MALFORMED)
            verdict["evidence"] = {
                "offending_first_bytes_hex": raw[:EVIDENCE_BYTES].hex(),
                "detail": str(exc),
            }
            return self._finish(verdict)

        results = []
        for chunk in packet.chunks:
            if isinstance(chunk, DataChunk):
                outcome = self._apply_data(index, chunk)
            elif isinstance(chunk, ForwardTsnChunk):
                outcome = self._apply_forward(index, chunk)
            else:
                outcome = {
                    "type": f"type-{chunk.ctype}",
                    "result": IGNORED,
                    "detail": "非 DATA/FORWARD-TSN 块，不在审查范围",
                }
            results.append(outcome)
            if outcome["result"] == REJECTED:
                break  # 报文整体冻结拒绝，后续块不再处理

        verdict["chunks"] = results
        rejected = next((r for r in results if r["result"] == REJECTED), None)
        if rejected is not None:
            verdict["verdict"] = REJECTED
            verdict["reason"] = rejected["reason"]
            verdict["evidence"] = rejected.get("evidence")
        elif not results or all(r["result"] == IGNORED for r in results):
            verdict["verdict"] = IGNORED
        elif any(r["result"] == ACCEPTED for r in results):
            verdict["verdict"] = ACCEPTED
        elif any(r["result"] == DUPLICATE for r in results):
            verdict["verdict"] = DUPLICATE
        else:
            verdict["verdict"] = STALE
        return self._finish(verdict)

    def _finish(self, verdict: dict) -> dict:
        # 每包处理后快照：累计 TSN / 缓存分片 / 跳过范围 / 已交付数
        verdict["state_after"] = self._state_snapshot()
        return verdict

    # ------------------------------------------------------------- DATA 块

    def _apply_data(self, index: int, chunk: DataChunk) -> dict:
        info = {
            "type": "DATA",
            "tsn": chunk.tsn,
            "stream": chunk.stream,
            "ssn": chunk.ssn,
            "begin": chunk.begin,
            "end": chunk.end,
            "unordered": chunk.unordered,
            "length": len(chunk.payload),
        }

        if chunk.unordered:
            return self._reject(info, R_UNORDERED, chunk,
                                "U=1 无序 DATA 不属于被审查的有序流")

        # 重传 / 冲突：先于一切窗口判断，旧 TSN 也能识别
        previous = self.received.get(chunk.tsn)
        if previous is not None:
            if previous == chunk.raw:
                info.update(result=DUPLICATE,
                            detail="字节完全相同的重传，不改变状态与消息数")
                return info
            return self._reject(
                info, R_TSN_CONFLICT, chunk,
                "同一 TSN 的字节与首次接收不一致",
                extra_evidence={
                    "original_packet_index": self.received_at[chunk.tsn],
                    "original_first_bytes_hex": previous[:EVIDENCE_BYTES].hex(),
                    "original_payload_prefix_hex":
                        previous[16:16 + EVIDENCE_BYTES].hex(),
                })

        # 已被 FORWARD-TSN 跨越的旧片段：补交不改变结论
        if self.forward_floor is not None and chunk.tsn <= self.forward_floor:
            info.update(result=STALE,
                        detail="TSN 已被 FORWARD-TSN 跨越，补交的旧片段被忽略")
            return info

        if self.stream_id is not None and chunk.stream != self.stream_id:
            return self._reject(info, R_ILLEGAL_STREAM, chunk,
                                f"DATA 属于流 {chunk.stream}，审计已绑定流 "
                                f"{self.stream_id}（单关联单流）")

        if chunk.ssn in self.skipped_ssns:
            info.update(result=STALE,
                        detail="所属消息已被 FORWARD-TSN 宣告放弃，片段被忽略")
            return info

        if chunk.ssn in self.delivered_ssns:
            return self._reject(info, R_ILLEGAL_ORDER, chunk,
                                f"消息 ssn={chunk.ssn} 已交付，新片段非法")

        if self.expected_ssn is not None and chunk.ssn != self.expected_ssn:
            return self._reject(info, R_ILLEGAL_ORDER, chunk,
                                f"分片 ssn={chunk.ssn}，但下一个应交付的流序为 "
                                f"ssn={self.expected_ssn}")

        if self.stream_id is None:  # 首个被接受的 DATA 绑定流与起始流序
            self.stream_id = chunk.stream
            self.expected_ssn = chunk.ssn

        frags = self.buffer.setdefault(chunk.ssn, {})
        if chunk.begin and any(f["begin"] for f in frags.values()):
            return self._reject(info, R_ILLEGAL_ORDER, chunk,
                                "同一消息出现第二个 BEGIN 分片")
        if chunk.end and any(f["end"] for f in frags.values()):
            return self._reject(info, R_ILLEGAL_ORDER, chunk,
                                "同一消息出现第二个 END 分片")

        frags[chunk.tsn] = {
            "begin": chunk.begin,
            "end": chunk.end,
            "length": len(chunk.payload),
            "data": chunk.payload,
        }
        self.received[chunk.tsn] = chunk.raw
        self.received_at[chunk.tsn] = index

        if self._is_complete(frags):
            ordered = [frags[t] for t in sorted(frags)]
            data = b"".join(f["data"] for f in ordered)
            message = {
                "ssn": chunk.ssn,
                "stream": chunk.stream,
                "tsn_first": min(frags),
                "tsn_last": max(frags),
                "fragments": len(frags),
                "length": len(data),
                "data_b64": base64.b64encode(data).decode("ascii"),
            }
            self.delivered.append(message)
            self.delivered_ssns.add(chunk.ssn)
            del self.buffer[chunk.ssn]
            self.expected_ssn = (chunk.ssn + 1) & 0xFFFF
            info.update(result=ACCEPTED,
                        detail=f"消息 ssn={chunk.ssn} 重组完成并交付",
                        delivered={"ssn": chunk.ssn, "length": len(data)})
        else:
            info.update(result=ACCEPTED, detail="分片已缓存，等待补齐")
        return info

    @staticmethod
    def _is_complete(frags: dict[int, dict]) -> bool:
        tsns = sorted(frags)
        first, last = tsns[0], tsns[-1]
        if not frags[first]["begin"] or not frags[last]["end"]:
            return False
        return last - first + 1 == len(tsns)  # TSN 连续覆盖 B..E

    # ------------------------------------------------------- FORWARD-TSN 块

    def _apply_forward(self, index: int, chunk: ForwardTsnChunk) -> dict:
        info = {
            "type": "FORWARD-TSN",
            "new_cum_tsn": chunk.new_cum_tsn,
            "pairs": [{"stream": s, "ssn": q} for s, q in chunk.pairs],
        }
        cum = self._cum_tsn()
        if cum is None:
            return self._reject(info, R_SKIP_BOUNDS, chunk,
                                "尚未收到任何 DATA，无 TSN 基线，跳过越界")
        if chunk.new_cum_tsn <= cum:
            return self._reject(info, R_SKIP_BOUNDS, chunk,
                                f"新累计 TSN {chunk.new_cum_tsn} 未推进当前累计 "
                                f"TSN {cum}，跳过越界")

        # 被跳过的是缓存中未完成消息所需的 TSN 时，FORWARD-TSN 必须列出该
        # (stream, ssn)，否则属于不合法的残缺跳过。
        if self.expected_ssn in self.buffer:
            frags = self.buffer[self.expected_ssn]
            if self._skip_breaks_message(frags, chunk.new_cum_tsn):
                listed = any(s == self.stream_id and q == self.expected_ssn
                             for s, q in chunk.pairs)
                if not listed:
                    return self._reject(
                        info, R_SKIP_MISSING, chunk,
                        f"跳过范围截断缓存中的消息 ssn={self.expected_ssn}，"
                        "但 FORWARD-TSN 未列出对应 (stream, ssn) 项")

        new_skipped = [t for t in range(cum + 1, chunk.new_cum_tsn + 1)
                       if t not in self.received]
        self.skipped_tsns.update(new_skipped)
        for run_start, run_end in self._runs(new_skipped):
            self._merge_range(run_start, run_end)

        for stream, ssn in sorted(chunk.pairs, key=lambda p: p[1]):
            if stream != self.stream_id or ssn in self.delivered_ssns:
                continue  # 非被审查流或已交付的消息不在处理范围
            self.skipped_ssns.add(ssn)
            self.buffer.pop(ssn, None)
            if ssn == self.expected_ssn:
                self.expected_ssn = (ssn + 1) & 0xFFFF

        self.forward_floor = chunk.new_cum_tsn
        info.update(result=ACCEPTED,
                    detail=f"累计 TSN 推进 {cum} -> {chunk.new_cum_tsn}",
                    skipped_tsns=new_skipped)
        return info

    @staticmethod
    def _skip_breaks_message(frags: dict[int, dict], new_cum: int) -> bool:
        tsns = sorted(frags)
        lo, hi = tsns[0], tsns[-1]
        for tsn in range(lo, hi + 1):  # 缓存区间内部空洞被跨越
            if tsn not in frags and tsn <= new_cum:
                return True
        # 消息尚未收齐 END，而跳过越过了已缓存的最高 TSN
        return not frags[hi]["end"] and new_cum > hi

    # ---------------------------------------------------------------- 工具

    def _reject(self, info: dict, reason: str, chunk, detail: str,
                extra_evidence: dict | None = None) -> dict:
        info.update(result=REJECTED, reason=reason, detail=detail)
        evidence = {"offending_first_bytes_hex": chunk.raw[:EVIDENCE_BYTES].hex()}
        if extra_evidence:
            evidence.update(extra_evidence)
        info["evidence"] = evidence
        return info
