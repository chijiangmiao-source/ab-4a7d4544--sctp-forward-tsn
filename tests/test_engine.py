import base64
import json
import unittest

from app.audit import AuditEngine
from tests.packets import (
    corrupt_checksum,
    data_chunk,
    forward_tsn_chunk,
    heartbeat_chunk,
    packet,
)


def run(packets):
    engine = AuditEngine()
    engine.process(packets)
    return engine


class OutOfOrderTest(unittest.TestCase):
    """乱序互补的 DATA：仅交付一次完整消息，且每包缓存变化可见。"""

    def test_end_fragment_arrives_first(self):
        p_end = packet([data_chunk(202, 0, b"WORLD", begin=False, end=True)])
        p_begin = packet([data_chunk(201, 0, b"HELLO-", begin=True, end=False)])
        engine = run([p_end, p_begin])

        v0, v1 = engine.verdicts
        self.assertEqual(v0["verdict"], "accepted")
        # 第一包后：END 分片已缓存、无交付
        self.assertEqual(v0["state_after"]["buffered"][0]["fragments"][0]["tsn"], 202)
        self.assertEqual(v0["state_after"]["delivered_count"], 0)
        # 第二包后：缓存清空、交付一次
        self.assertEqual(v1["state_after"]["buffered"], [])
        self.assertEqual(v1["state_after"]["delivered_count"], 1)

        self.assertEqual(len(engine.delivered), 1)
        msg = engine.delivered[0]
        self.assertEqual((msg["tsn_first"], msg["tsn_last"]), (201, 202))
        self.assertEqual(base64.b64decode(msg["data_b64"]), b"HELLO-WORLD")
        self.assertEqual(engine._cum_tsn(), 202)


class ForwardSkipTest(unittest.TestCase):
    """缺失片段被合法 FORWARD-TSN 跨越：不交付残缺消息，补交旧片段不改变结论。"""

    def test_skip_then_late_fragment(self):
        p_data = packet([data_chunk(301, 0, b"abc", begin=True, end=False)])
        p_fwd = packet([forward_tsn_chunk(302, [(0, 0)])])
        p_late = packet([data_chunk(302, 0, b"def", begin=False, end=True)])
        p_next = packet([data_chunk(303, 1, b"next")])
        engine = run([p_data, p_fwd, p_late, p_next])

        v = engine.verdicts
        self.assertEqual(v[0]["verdict"], "accepted")
        self.assertEqual(v[1]["verdict"], "accepted")
        self.assertEqual(v[1]["state_after"]["skipped_ranges"], [[302, 302]])
        self.assertEqual(v[1]["state_after"]["skipped_ssns"], [0])
        self.assertEqual(v[1]["state_after"]["buffered"], [])
        # 补交旧片段 => stale，结论不变
        self.assertEqual(v[2]["verdict"], "stale")
        self.assertEqual(v[2]["state_after"]["delivered_count"], 0)
        # 后续新消息正常交付
        self.assertEqual(v[3]["verdict"], "accepted")
        self.assertEqual(len(engine.delivered), 1)
        self.assertEqual(engine.delivered[0]["ssn"], 1)
        self.assertEqual(engine._cum_tsn(), 303)

    def test_skip_without_pair_is_rejected(self):
        p_data = packet([data_chunk(301, 0, b"abc", begin=True, end=False)])
        p_fwd = packet([forward_tsn_chunk(302, [])])  # 未列出 (0,0)
        engine = run([p_data, p_fwd])
        self.assertEqual(engine.verdicts[1]["verdict"], "rejected")
        self.assertEqual(engine.verdicts[1]["reason"],
                         "skip-missing-stream-entry")

    def test_skipped_ranges_exclude_received_tsns(self):
        # 已收到的 TSN 不属于跳过范围
        p1 = packet([data_chunk(301, 0, b"a", begin=True, end=False)])
        p2 = packet([data_chunk(303, 0, b"b", begin=False, end=True)])
        p_fwd = packet([forward_tsn_chunk(305, [(0, 0)])])
        engine = run([p1, p2, p_fwd])
        state = engine.verdicts[2]["state_after"]
        self.assertEqual(state["skipped_ranges"], [[302, 302], [304, 305]])
        self.assertEqual(engine._cum_tsn(), 305)


class RetransmissionTest(unittest.TestCase):
    def test_byte_identical_retransmission_is_idempotent(self):
        p = packet([data_chunk(401, 0, b"msg")])
        engine = run([p, p, p])
        self.assertEqual([v["verdict"] for v in engine.verdicts],
                         ["accepted", "duplicate", "duplicate"])
        self.assertEqual(len(engine.delivered), 1)

    def test_same_tsn_different_bytes_is_frozen_reject(self):
        p1 = packet([data_chunk(501, 0, b"AAAA")])
        p2 = packet([data_chunk(501, 0, b"BBBB")])
        engine = run([p1, p2])
        v = engine.verdicts[1]
        self.assertEqual(v["verdict"], "rejected")
        self.assertEqual(v["reason"], "tsn-conflict")
        # 稳定显示首个原始字节依据
        evidence = v["evidence"]
        self.assertEqual(evidence["original_packet_index"], 0)
        self.assertEqual(evidence["original_first_bytes_hex"],
                         data_chunk(501, 0, b"AAAA")[:16].hex())
        self.assertEqual(evidence["original_payload_prefix_hex"],
                         b"AAAA".hex())
        self.assertEqual(len(engine.delivered), 1)  # 首个包交付的结论不变


class IllegalTest(unittest.TestCase):
    def test_wrong_stream(self):
        p1 = packet([data_chunk(601, 0, b"a", stream=0)])
        p2 = packet([data_chunk(602, 1, b"b", stream=1)])
        engine = run([p1, p2])
        self.assertEqual(engine.verdicts[1]["verdict"], "rejected")
        self.assertEqual(engine.verdicts[1]["reason"], "illegal-stream")

    def test_ssn_jump(self):
        p1 = packet([data_chunk(601, 0, b"a", begin=True, end=False)])
        p2 = packet([data_chunk(602, 1, b"b")])
        engine = run([p1, p2])
        self.assertEqual(engine.verdicts[1]["verdict"], "rejected")
        self.assertEqual(engine.verdicts[1]["reason"], "illegal-stream-order")

    def test_duplicate_begin(self):
        p1 = packet([data_chunk(601, 0, b"a", begin=True, end=False)])
        p2 = packet([data_chunk(602, 0, b"b", begin=True, end=False)])
        engine = run([p1, p2])
        self.assertEqual(engine.verdicts[1]["verdict"], "rejected")
        self.assertEqual(engine.verdicts[1]["reason"], "illegal-stream-order")

    def test_fragment_for_delivered_message(self):
        p1 = packet([data_chunk(601, 0, b"a")])
        p2 = packet([data_chunk(602, 0, b"b", begin=True, end=False)])
        engine = run([p1, p2])
        self.assertEqual(engine.verdicts[1]["verdict"], "rejected")
        self.assertEqual(engine.verdicts[1]["reason"], "illegal-stream-order")

    def test_unordered_data(self):
        p = packet([data_chunk(601, 0, b"a", unordered=True)])
        engine = run([p])
        self.assertEqual(engine.verdicts[0]["verdict"], "rejected")
        self.assertEqual(engine.verdicts[0]["reason"], "unordered-data")


class SkipBoundsTest(unittest.TestCase):
    def test_non_advancing_skip_is_rejected(self):
        p1 = packet([data_chunk(701, 0, b"a")])  # 累计 TSN = 701
        p_same = packet([forward_tsn_chunk(701, [])])
        p_back = packet([forward_tsn_chunk(700, [])])
        p_ok = packet([forward_tsn_chunk(703, [])])
        engine = run([p1, p_same, p_back, p_ok])
        v = engine.verdicts
        self.assertEqual(v[1]["verdict"], "rejected")
        self.assertEqual(v[1]["reason"], "skip-out-of-bounds")
        self.assertEqual(v[2]["verdict"], "rejected")
        self.assertEqual(v[2]["reason"], "skip-out-of-bounds")
        self.assertEqual(v[3]["verdict"], "accepted")
        self.assertEqual(v[3]["state_after"]["skipped_ranges"], [[702, 703]])

    def test_skip_without_baseline_is_rejected(self):
        engine = run([packet([forward_tsn_chunk(10, [])])])
        self.assertEqual(engine.verdicts[0]["verdict"], "rejected")
        self.assertEqual(engine.verdicts[0]["reason"], "skip-out-of-bounds")


class PacketLevelTest(unittest.TestCase):
    def test_bad_checksum(self):
        p = corrupt_checksum(packet([data_chunk(801, 0, b"a")]))
        engine = run([p])
        v = engine.verdicts[0]
        self.assertEqual(v["verdict"], "rejected")
        self.assertEqual(v["reason"], "bad-checksum")
        self.assertIn("offending_first_bytes_hex", v["evidence"])

    def test_malformed(self):
        engine = run([b"\x00\x01\x02"])
        self.assertEqual(engine.verdicts[0]["verdict"], "rejected")
        self.assertEqual(engine.verdicts[0]["reason"], "malformed-packet")

    def test_opaque_chunk_ignored(self):
        engine = run([packet([heartbeat_chunk()])])
        self.assertEqual(engine.verdicts[0]["verdict"], "ignored")


class DeterminismTest(unittest.TestCase):
    def test_same_capture_same_result(self):
        capture = [
            packet([data_chunk(902, 0, b"E2", begin=False, end=True)]),
            packet([data_chunk(901, 0, b"B1", begin=True, end=False)]),
            packet([data_chunk(901, 0, b"B1", begin=True, end=False)]),
            packet([data_chunk(901, 0, b"XX", begin=True, end=False)]),
            packet([forward_tsn_chunk(905, [])]),
        ]
        first = json.dumps(run(capture).result(), sort_keys=True)
        second = json.dumps(run(capture).result(), sort_keys=True)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
