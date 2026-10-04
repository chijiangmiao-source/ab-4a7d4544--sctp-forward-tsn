import tempfile
import unittest

from app.store import AuditStore


class StoreTest(unittest.TestCase):
    def test_put_get_and_frozen(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditStore(tmp)
            payload = {"audit_id": "a-1", "verdicts": [{"index": 0}]}
            self.assertTrue(store.put("a-1", payload))
            self.assertFalse(store.put("a-1", {"other": True}))  # 已冻结
            self.assertEqual(store.get("a-1"), payload)
            self.assertIsNone(store.get("missing"))

    def test_reload_from_disk_is_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = {"audit_id": "a-2", "messages": [{"ssn": 0}],
                       "final_state": {"cum_tsn": 5}}
            AuditStore(tmp).put("a-2", payload)
            reloaded = AuditStore(tmp).get("a-2")  # 新实例从磁盘读
            self.assertEqual(reloaded, payload)

    def test_id_validation(self):
        self.assertTrue(AuditStore.valid_id("orbit-relay.01"))
        self.assertFalse(AuditStore.valid_id(""))
        self.assertFalse(AuditStore.valid_id("../escape"))
        self.assertFalse(AuditStore.valid_id("a/b"))
        self.assertFalse(AuditStore.valid_id(None))


if __name__ == "__main__":
    unittest.main()
