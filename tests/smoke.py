"""针对运行中服务的 API/HTTP 冒烟：覆盖验收描述的全部关键行为。"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.request

from tests.packets import (
    b64,
    corrupt_checksum,
    data_chunk,
    forward_tsn_chunk,
    packet,
)


def _http(method: str, url: str, payload=None):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read()
            return resp.status, body
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _json(method: str, url: str, payload=None):
    status, body = _http(method, url, payload)
    try:
        return status, json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return status, None


def run(base_url: str) -> list[str]:
    failures: list[str] = []

    def check(name: str, cond: bool, extra: str = "") -> None:
        if cond:
            print(f"  ok    {name}", flush=True)
        else:
            print(f"  FAIL  {name}  {extra}", flush=True)
            failures.append(name)

    # ---- 健康与操作页
    status, body = _json("GET", f"{base_url}/health")
    check("health", status == 200 and body and body.get("status") == "ok",
          f"status={status} body={body}")
    status, body = _http("GET", f"{base_url}/")
    check("operation-page", status == 200 and "审计标识".encode() in body,
          f"status={status}")

    # ---- 主审计：乱序/重传/冲突/跨越/补交/非法/越界 全场景
    aid = f"smoke-main-{int(time.time() * 1000)}"
    p0 = packet([data_chunk(101, 0, b"hello-", begin=True, end=False)])
    p1 = packet([data_chunk(102, 0, b"world", begin=False, end=True)])
    p2 = p0                                             # 字节完全相同的重传
    p3 = packet([data_chunk(101, 0, b"HELLO!", begin=True, end=False)])
    p4 = packet([data_chunk(104, 1, b"part1-", begin=True, end=False)])
    p5 = packet([forward_tsn_chunk(105, [(0, 1)])])     # 合法跨越缺失片段
    p6 = packet([data_chunk(105, 1, b"part2", begin=False, end=True)])
    p7 = packet([forward_tsn_chunk(105, [])])           # 越界：未推进
    p8 = packet([data_chunk(106, 2, b"x", stream=1)])   # 非法流
    p9 = packet([data_chunk(106, 3, b"x")])             # 非法流序
    p10 = packet([data_chunk(106, 2, b"done")])
    p11 = corrupt_checksum(packet([data_chunk(107, 2, b"y")]))
    capture = [p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11]

    status, created = _json("POST", f"{base_url}/api/audits",
                            {"audit_id": aid, "packets": [b64(p) for p in capture]})
    check("create-201", status == 201, f"status={status} body={created}")
    if status != 201:
        return failures + ["main-audit-abort"]

    verdicts = created["verdicts"]
    expected = ["accepted", "accepted", "duplicate", "rejected",
                "accepted", "accepted", "stale", "rejected",
                "rejected", "rejected", "accepted", "rejected"]
    check("verdict-sequence",
          [v["verdict"] for v in verdicts] == expected,
          f"got={[v['verdict'] for v in verdicts]}")
    check("reason-tsn-conflict", verdicts[3]["reason"] == "tsn-conflict")
    check("reason-skip-bounds", verdicts[7]["reason"] == "skip-out-of-bounds")
    check("reason-illegal-stream", verdicts[8]["reason"] == "illegal-stream")
    check("reason-illegal-order",
          verdicts[9]["reason"] == "illegal-stream-order")
    check("reason-bad-checksum", verdicts[11]["reason"] == "bad-checksum")

    # 消息数：重传不增加；跨越不交付残缺；补交旧片段不改变结论
    messages = created["messages"]
    check("message-count", len(messages) == 2,
          f"got={len(messages)}")
    if len(messages) == 2:
        check("message-0-data",
              base64.b64decode(messages[0]["data_b64"]) == b"hello-world")
        check("message-1-data",
              base64.b64decode(messages[1]["data_b64"]) == b"done")
    check("stale-kept-conclusion",
          verdicts[6]["state_after"]["delivered_count"] == 1)

    # 首个原始字节依据
    evidence = verdicts[3].get("evidence") or {}
    check("evidence-original-bytes",
          evidence.get("original_first_bytes_hex")
          == data_chunk(101, 0, b"hello-", begin=True, end=False)[:16].hex()
          and evidence.get("original_packet_index") == 0,
          f"evidence={evidence}")

    # 跳过范围与缓存变化可见
    check("skipped-range-visible",
          [105, 105] in verdicts[5]["state_after"]["skipped_ranges"])
    check("buffer-change-visible",
          verdicts[0]["state_after"]["buffered"] != []
          and verdicts[1]["state_after"]["buffered"] == [])

    # ---- 同一标识重读：逐包裁决与消息列表与首次一致
    status, reread = _json("GET", f"{base_url}/api/audits/{aid}")
    check("reread-200", status == 200)
    check("reread-identical", reread == created)
    status, again = _json("POST", f"{base_url}/api/audits",
                          {"audit_id": aid, "packets": [b64(p0)]})
    check("resubmit-409", status == 409, f"status={status}")
    status, reread2 = _json("GET", f"{base_url}/api/audits/{aid}")
    check("reread-still-identical", reread2 == created)

    # ---- 乱序互补：END 先到，仅交付一次完整消息
    aid2 = f"smoke-ooo-{int(time.time() * 1000)}"
    q0 = packet([data_chunk(202, 0, b"WORLD", begin=False, end=True)])
    q1 = packet([data_chunk(201, 0, b"HELLO-", begin=True, end=False)])
    status, ooo = _json("POST", f"{base_url}/api/audits",
                        {"audit_id": aid2, "packets": [b64(q0), b64(q1)]})
    check("ooo-create", status == 201, f"status={status}")
    if status == 201:
        check("ooo-single-message", len(ooo["messages"]) == 1)
        if ooo["messages"]:
            check("ooo-message-data",
                  base64.b64decode(ooo["messages"][0]["data_b64"])
                  == b"HELLO-WORLD")
        check("ooo-buffer-visible",
              ooo["verdicts"][0]["state_after"]["buffered"][0]["fragments"][0]["tsn"] == 202)

    # ---- 入参约束
    status, _ = _json("POST", f"{base_url}/api/audits",
                      {"audit_id": f"smoke-big-{int(time.time() * 1000)}",
                       "packets": [b64(p0)] * 33})
    check("too-many-400", status == 400, f"status={status}")
    status, _ = _json("POST", f"{base_url}/api/audits",
                      {"audit_id": f"smoke-b64-{int(time.time() * 1000)}",
                       "packets": ["!!!not-base64!!!"]})
    check("bad-base64-400", status == 400, f"status={status}")
    status, _ = _json("GET", f"{base_url}/api/audits/no-such-audit")
    check("unknown-404", status == 404, f"status={status}")

    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    args = parser.parse_args()
    failures = run(args.base_url)
    if failures:
        print(f"smoke FAILED: {failures}", flush=True)
        return 1
    print("smoke OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
