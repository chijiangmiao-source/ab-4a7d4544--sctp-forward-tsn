"""HTTP 入口：操作页、JSON API 与健康响应。

路由
----
GET  /                      操作页（提交捕获 / 重新打开已冻结裁决）
GET  /audit?id=<标识>       操作页 + 指定审计的冻结裁决
POST /audit                 操作页表单提交（audit_id + 每行一个 Base64 包）
GET  /health                健康响应 {"status": "ok"}
POST /api/audits            创建审计 {"audit_id": str, "packets": [base64, ...]}
GET  /api/audits/<id>       读取已冻结的逐包裁决与消息列表（与首次一致）
"""
from __future__ import annotations

import base64
import binascii
import html
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .audit import MAX_PACKETS, AuditEngine
from .store import AuditStore
from .sctp import MAX_PACKET_SIZE

MAX_BODY_BYTES = 2 * 1024 * 1024

STORE = AuditStore(
    os.environ.get("AUDIT_DATA_DIR", os.path.join(os.getcwd(), "data", "audits"))
)

VERDICT_ZH = {
    "accepted": "接受",
    "duplicate": "重复·幂等",
    "stale": "过期·忽略",
    "ignored": "无需审查",
    "rejected": "冻结拒绝",
}

REASON_ZH = {
    "bad-checksum": "CRC32C 校验失败",
    "malformed-packet": "报文结构非法",
    "tsn-conflict": "同一 TSN 字节冲突",
    "illegal-stream": "非法流（非被审查流）",
    "illegal-stream-order": "非法流序",
    "unordered-data": "无序 DATA（U=1）",
    "skip-out-of-bounds": "越界跳过",
    "skip-missing-stream-entry": "跳过缺少 (stream, ssn) 项",
}


# ------------------------------------------------------------------ 业务


def create_audit(audit_id, packets_b64) -> tuple[int, dict]:
    """校验输入、逐包裁决并冻结存储；返回 (HTTP 状态码, 响应体)。"""
    if not AuditStore.valid_id(audit_id):
        return 400, {"error": "invalid-audit-id",
                     "detail": "审计标识须为 1-128 位字母数字或 . _ -，"
                               "且以字母数字开头"}
    if not isinstance(packets_b64, list) or not packets_b64:
        return 400, {"error": "invalid-packets", "detail": "packets 须为非空数组"}
    if len(packets_b64) > MAX_PACKETS:
        return 400, {"error": "too-many-packets",
                     "detail": f"单次至多提交 {MAX_PACKETS} 个包，"
                               f"实际 {len(packets_b64)} 个"}

    raws = []
    for i, item in enumerate(packets_b64):
        if not isinstance(item, str):
            return 400, {"error": "invalid-packets",
                         "detail": f"第 {i} 个包不是 Base64 字符串"}
        try:
            raw = base64.b64decode(item, validate=True)
        except (binascii.Error, ValueError):
            return 400, {"error": "invalid-base64",
                         "detail": f"第 {i} 个包 Base64 解码失败"}
        if not raw or len(raw) > MAX_PACKET_SIZE:
            return 400, {"error": "invalid-packets",
                         "detail": f"第 {i} 个包长度非法: {len(raw)} 字节"}
        raws.append(raw)

    engine = AuditEngine()
    engine.process(raws)
    result = {"audit_id": audit_id, "packet_count": len(raws), "frozen": True}
    result.update(engine.result())

    if not STORE.put(audit_id, result):
        return 409, {"error": "audit-exists",
                     "detail": "审计标识已存在，逐包裁决已冻结；"
                               "请用 GET /api/audits/<id> 重新打开",
                     "audit_id": audit_id}
    return 201, STORE.get(audit_id)


# ------------------------------------------------------------------ 页面

_PAGE_HEAD = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>星载控制中继 · 弱链路 SCTP 审计操作页</title>
<style>
body{font-family:system-ui,"PingFang SC","Microsoft YaHei",sans-serif;
margin:0;background:#f4f6f8;color:#1c2733}
main{max-width:1180px;margin:0 auto;padding:1.5rem}
h1{font-size:1.35rem} h2{font-size:1.05rem;margin-top:0}
.card{background:#fff;border:1px solid #dde3e8;border-radius:8px;
padding:1rem 1.25rem;margin-bottom:1.25rem}
label{display:block;margin:.5rem 0 .25rem;font-weight:600}
input[type=text]{width:22rem;max-width:100%;padding:.4rem}
textarea{width:100%;padding:.4rem;font-family:ui-monospace,monospace}
button{margin-top:.6rem;padding:.45rem 1.2rem;border:0;border-radius:6px;
background:#0b5fff;color:#fff;font-size:.95rem;cursor:pointer}
table{border-collapse:collapse;width:100%;font-size:.86rem}
th,td{border:1px solid #d5dde3;padding:.35rem .5rem;text-align:left;
vertical-align:top}
th{background:#eef2f5}
code,pre,.mono{font-family:ui-monospace,SFMono-Regular,monospace}
pre{background:#0f1720;color:#d7e3ee;padding:.8rem;border-radius:6px;
overflow:auto;font-size:.8rem}
.v-accepted{color:#0a7d2c;font-weight:700}
.v-rejected{color:#c01616;font-weight:700}
.v-duplicate,.v-stale,.v-ignored{color:#6b7684;font-weight:700}
.error{background:#fdecec;border:1px solid #f2b8b8;color:#8f1d1d;
padding:.7rem 1rem;border-radius:6px;margin-bottom:1rem}
footer{color:#6b7684;font-size:.82rem;margin-top:1rem}
</style></head><body><main>
<h1>星载控制中继 · 弱链路 SCTP 审计操作页</h1>
"""


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _fmt_state(state: dict) -> str:
    buffered = "; ".join(
        f"ssn{b['ssn']}:["
        + " ".join(f"tsn{f['tsn']}{'B' if f['begin'] else ''}"
                   f"{'E' if f['end'] else ''}"
                   for f in b["fragments"])
        + "]"
        for b in state["buffered"]
    ) or "空"
    skipped = ", ".join(f"{lo}-{hi}" if lo != hi else str(lo)
                        for lo, hi in state["skipped_ranges"]) or "无"
    cum = state["cum_tsn"] if state["cum_tsn"] is not None else "—"
    return (f"累计TSN={cum} ｜ 缓存分片: {buffered} ｜ 跳过范围: {skipped}"
            f" ｜ 已交付={state['delivered_count']}")


def _fmt_chunk(chunk: dict) -> str:
    if chunk["type"] == "DATA":
        head = (f"DATA tsn={chunk['tsn']} stream={chunk['stream']} "
                f"ssn={chunk['ssn']} B={int(chunk['begin'])} "
                f"E={int(chunk['end'])} len={chunk['length']}")
    elif chunk["type"] == "FORWARD-TSN":
        pairs = " ".join(f"({p['stream']},{p['ssn']})"
                         for p in chunk.get("pairs", [])) or "无"
        head = f"FORWARD-TSN new_cum={chunk['new_cum_tsn']} 项: {pairs}"
    else:
        head = chunk["type"]
    result = VERDICT_ZH.get(chunk.get("result"), chunk.get("result", ""))
    detail = chunk.get("detail", "")
    return f"{head} → {result}（{detail}）"


def _fmt_evidence(evidence) -> str:
    if not evidence:
        return "—"
    labels = {
        "original_packet_index": "首个原始包序号",
        "original_first_bytes_hex": "首个原始字节(块头)",
        "original_payload_prefix_hex": "首个原始字节(载荷)",
        "offending_first_bytes_hex": "冲突包首字节",
        "expected_crc32c": "校验和字段",
        "computed_crc32c": "实算校验和",
        "detail": "说明",
    }
    return "<br>".join(
        f"{_esc(labels.get(k, k))}={_esc(v)}" for k, v in evidence.items()
    )


def render_result(result: dict) -> str:
    out = ['<section class="card"><h2>审计 ',
           f"<code>{_esc(result['audit_id'])}</code> 的冻结裁决</h2>"]
    final = result["final_state"]
    out.append("<p>"
               f"数据包数: <b>{result['packet_count']}</b> ｜ "
               f"已交付消息: <b>{len(result['messages'])}</b> ｜ "
               f"审查流: <b>{final['stream_id']}</b> ｜ "
               f"下一期望流序: <b>{final['expected_ssn']}</b> ｜ "
               f"状态: <b>已冻结</b></p>")

    out.append("<h3>已交付消息</h3>")
    if result["messages"]:
        out.append("<table><tr><th>#</th><th>流序 SSN</th><th>TSN 范围</th>"
                   "<th>分片数</th><th>长度</th><th>数据 (Base64)</th></tr>")
        for i, msg in enumerate(result["messages"]):
            out.append(
                f"<tr><td>{i}</td><td>{msg['ssn']}</td>"
                f"<td>{msg['tsn_first']}–{msg['tsn_last']}</td>"
                f"<td>{msg['fragments']}</td><td>{msg['length']}</td>"
                f"<td class='mono'>{_esc(msg['data_b64'])}</td></tr>")
        out.append("</table>")
    else:
        out.append("<p>无（缺失片段被跨越后不交付残缺消息）。</p>")

    out.append("<h3>逐包裁决（按捕获顺序）</h3>"
               "<table><tr><th>#</th><th>裁决</th><th>原因</th>"
               "<th>块处理</th><th>首字节依据</th><th>处理后状态</th></tr>")
    for verdict in result["verdicts"]:
        css = f"v-{verdict['verdict']}"
        label = VERDICT_ZH.get(verdict["verdict"], verdict["verdict"])
        reason = verdict.get("reason") or "—"
        reason_zh = REASON_ZH.get(reason, reason)
        chunks = "<br>".join(_esc(_fmt_chunk(c)) for c in verdict["chunks"]) or "—"
        out.append(
            f"<tr><td>{verdict['index']}</td>"
            f"<td class='{css}'>{label}</td>"
            f"<td>{_esc(reason_zh)}</td>"
            f"<td>{chunks}</td>"
            f"<td class='mono'>{_fmt_evidence(verdict.get('evidence'))}</td>"
            f"<td class='mono'>{_esc(_fmt_state(verdict['state_after']))}</td>"
            f"</tr>")
    out.append("</table>")

    pretty = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)
    out.append("<details><summary>原始 JSON</summary>"
               f"<pre>{_esc(pretty)}</pre></details></section>")
    return "".join(out)


def render_page(result=None, error=None, prefill_id="", prefill_packets="") -> str:
    parts = [_PAGE_HEAD]
    parts.append(f"""
<section class="card">
<h2>提交捕获包（按捕获顺序，每行一个 Base64，至多 {MAX_PACKETS} 个）</h2>
<form method="post" action="/audit">
<label>稳定审计标识</label>
<input type="text" name="audit_id" required maxlength="128"
 pattern="[A-Za-z0-9][A-Za-z0-9._-]*" value="{_esc(prefill_id)}">
<label>Base64 数据包</label>
<textarea name="packets" rows="9" required>{_esc(prefill_packets)}</textarea>
<br><button type="submit">提交并冻结逐包裁决</button>
</form></section>
<section class="card">
<h2>重新打开已冻结裁决</h2>
<form method="get" action="/audit">
<label>审计标识</label>
<input type="text" name="id" required value="{_esc(prefill_id)}">
<button type="submit">打开</button>
</form></section>""")
    if error:
        parts.append(f'<div class="error">{_esc(error)}</div>')
    if result:
        parts.append(render_result(result))
    parts.append("<footer>API: <code>POST /api/audits</code> ｜ "
                 "<code>GET /api/audits/&lt;id&gt;</code> ｜ "
                 "<code>GET /health</code></footer></main></body></html>")
    return "".join(parts)


# ------------------------------------------------------------------ HTTP


class Handler(BaseHTTPRequestHandler):
    server_version = "SctpRelayAudit/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):  # 静默访问日志
        pass

    # ---- 响应工具
    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False, sort_keys=True,
                          indent=2).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _html(self, status: int, markup: str) -> None:
        self._send(status, markup.encode("utf-8"), "text/html; charset=utf-8")

    def _read_body(self) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            return None
        return self.rfile.read(length)

    # ---- GET
    def do_GET(self) -> None:
        url = urlparse(self.path)
        path = url.path
        if path == "/health":
            return self._json(200, {"status": "ok"})
        if path in ("/", "/audit"):
            audit_id = parse_qs(url.query).get("id", [""])[0].strip()
            if not audit_id:
                return self._html(200, render_page())
            result = STORE.get(audit_id) if AuditStore.valid_id(audit_id) else None
            if result is None:
                return self._html(404, render_page(
                    error=f"审计标识 “{audit_id}” 不存在或非法",
                    prefill_id=audit_id))
            return self._html(200, render_page(result=result,
                                               prefill_id=audit_id))
        if path.startswith("/api/audits/"):
            audit_id = path[len("/api/audits/"):]
            if not AuditStore.valid_id(audit_id):
                return self._json(404, {"error": "not-found"})
            result = STORE.get(audit_id)
            if result is None:
                return self._json(404, {"error": "not-found",
                                        "audit_id": audit_id})
            return self._json(200, result)
        return self._json(404, {"error": "not-found"})

    # ---- POST
    def do_POST(self) -> None:
        url = urlparse(self.path)
        path = url.path
        body = self._read_body()
        if body is None:
            return self._json(400, {"error": "invalid-body"})

        if path == "/api/audits":
            try:
                payload = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return self._json(400, {"error": "invalid-json"})
            if not isinstance(payload, dict):
                return self._json(400, {"error": "invalid-json"})
            status, response = create_audit(payload.get("audit_id"),
                                            payload.get("packets"))
            return self._json(status, response)

        if path == "/audit":
            form = parse_qs(body.decode("utf-8", errors="replace"))
            audit_id = form.get("audit_id", [""])[0].strip()
            packet_lines = [line.strip()
                            for line in form.get("packets", [""])[0].splitlines()
                            if line.strip()]
            status, response = create_audit(audit_id, packet_lines)
            if status == 201:
                return self._html(201, render_page(result=response,
                                                   prefill_id=audit_id))
            if status == 409:
                frozen = STORE.get(audit_id)
                return self._html(409, render_page(
                    result=frozen,
                    error="审计标识已存在：以下为首次提交时冻结的逐包裁决",
                    prefill_id=audit_id))
            return self._html(400, render_page(
                error=response.get("detail") or response.get("error"),
                prefill_id=audit_id,
                prefill_packets="\n".join(packet_lines)))

        return self._json(404, {"error": "not-found"})


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"sctp-relay-audit  listening on 0.0.0.0:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
