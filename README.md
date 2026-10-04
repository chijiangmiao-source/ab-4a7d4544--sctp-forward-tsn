# 星载控制中继 · 弱链路 SCTP 审计服务

星载控制中继在弱链路接收控制消息。审查员在操作页填写**稳定审计标识**，按捕获顺序
提交**至多 32 个 Base64 编码的 SCTP 包**；系统仅审查**单关联、单个有序流**中的
`DATA` 与 `FORWARD-TSN` 块，校验公共头与 CRC32C，依据 TSN 与 B/E 标志展示
**累计 TSN、缓存分片、跳过范围与已交付消息**，并冻结逐包裁决。以同一标识可重新
打开已冻结的裁决，重读结果与首次完全一致。

## 快速开始

```bash
# 启动操作页与健康响应（宿主端口可用 HOST_PORT 配置，默认 8080）
HOST_PORT=9000 docker compose up app

# 操作页:  http://localhost:9000/         健康响应: http://localhost:9000/health
```

```bash
# 一次性验证：代码测试 + 构建检查 + 对 app 的 API/HTTP 冒烟，
# 完成后退出并以退出码报告结果（0=通过，非 0=失败）
docker compose up verify --exit-code-from verify
echo $?
```

本地无 Docker 时：

```bash
python3 -m app.server &                      # PORT / AUDIT_DATA_DIR 可配
python3 -m tests.verify --base-url http://127.0.0.1:8080
```

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 操作页（提交捕获 / 重新打开已冻结裁决） |
| GET | `/audit?id=<标识>` | 操作页 + 指定审计的冻结裁决 |
| POST | `/audit` | 操作页表单提交（`audit_id` + 每行一个 Base64 包） |
| GET | `/health` | 健康响应 `{"status": "ok"}` |
| POST | `/api/audits` | 创建审计：`{"audit_id": "...", "packets": ["<base64>", ...]}` |
| GET | `/api/audits/<id>` | 读取已冻结的逐包裁决与消息列表（与首次一致） |

* 创建成功返回 `201`；标识已存在返回 `409`（裁决已冻结，不可改写）；
  包数超过 32、Base64 非法、标识非法等返回 `400`；未知标识返回 `404`。
* 审计标识：1–128 位字母数字或 `.` `_` `-`，以字母数字开头。

## 裁决语义

每个报文恰好得到一条冻结裁决（`verdicts[i]`），并附处理后的状态快照
（`state_after`：累计 TSN / 缓存分片 / 跳过范围 / 已交付数）：

| 裁决 | 含义 |
| --- | --- |
| `accepted` | 已处理：分片缓存、消息交付或累计 TSN 推进 |
| `duplicate` | 字节完全相同的 DATA 重传，不增加消息数 |
| `stale` | 被 FORWARD-TSN 跨越后补交的旧片段，忽略且结论不变 |
| `ignored` | 不含 DATA/FORWARD-TSN 块 |
| `rejected` | 冻结拒绝，附 `reason` 与首字节依据 `evidence` |

冻结拒绝原因：

| reason | 触发 |
| --- | --- |
| `bad-checksum` | CRC32C 校验失败 |
| `malformed-packet` | 公共头/块结构非法 |
| `tsn-conflict` | 同一 TSN 的字节与首次接收不一致（证据含首个原始包的块首字节与载荷前缀） |
| `illegal-stream` | DATA 属于其他流（审计仅绑定单关联单流） |
| `illegal-stream-order` | 非法流序：SSN 跳变、重复 B/E 分片、已交付消息的新分片 |
| `unordered-data` | U=1 无序 DATA 不属于被审查的有序流 |
| `skip-out-of-bounds` | FORWARD-TSN 未推进累计 TSN，或尚无 TSN 基线 |
| `skip-missing-stream-entry` | 跳过截断了缓存中的半成品消息但未列出对应 `(stream, ssn)` 项 |

## 验收行为

* **乱序互补的 DATA**：END 分片先到则缓存，BEGIN 到达后仅交付一次完整消息，
  每包缓存变化在 `state_after.buffered` 可见。
* **缺失片段被合法 FORWARD-TSN 跨越**：不交付残缺消息；随后补交旧片段
  裁决为 `stale`，消息列表不变。
* **字节完全相同的重传**：`duplicate`，消息数不增加。
* **同一 TSN 不同字节 / 非法流序 / 越界跳过**：冻结拒绝，稳定显示首个原始
  字节依据（`evidence.original_first_bytes_hex` 等）。
* **同一标识重读**：`GET /api/audits/<id>` 的逐包裁决与消息列表与首次一致；
  结果落盘（`AUDIT_DATA_DIR`），服务重启后仍一致。

## 目录结构

```
app/
  crc32c.py   CRC-32C（SCTP 校验和）
  sctp.py     公共头 + DATA / FORWARD-TSN 解析
  audit.py    逐包裁决引擎（重组、跳过、冻结拒绝）
  store.py    审计标识 -> 冻结结果（JSON 落盘）
  server.py   操作页 / JSON API / 健康响应
tests/
  packets.py      SCTP 报文构造工具
  test_*.py       单元测试
  smoke.py        API/HTTP 冒烟
  verify.py       verify 编排：单测 + 构建检查 + 冒烟，退出码报告
Dockerfile  docker-compose.yml
```

## 说明与假设

* TSN 按不回绕的 32 位序号处理（单次至多 32 包的捕获窗口假设不跨回绕点）。
* 审查范围外的块类型（如 HEARTBEAT）忽略，不影响裁决。
* 环境变量：`PORT`（容器内监听端口，默认 8080）、`AUDIT_DATA_DIR`
  （冻结结果目录）、`HOST_PORT`（Compose 宿主端口，默认 8080）。
