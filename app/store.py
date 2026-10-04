"""审计结果的冻结持久化：每个审计标识一个 JSON 文件，写入后不可变。"""
from __future__ import annotations

import json
import os
import re
import threading

AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class AuditStore:
    def __init__(self, directory: str) -> None:
        self._dir = directory
        self._cache: dict[str, dict] = {}
        self._lock = threading.Lock()
        os.makedirs(directory, exist_ok=True)

    @staticmethod
    def valid_id(audit_id) -> bool:
        return isinstance(audit_id, str) and bool(AUDIT_ID_RE.match(audit_id))

    def _path(self, audit_id: str) -> str:
        return os.path.join(self._dir, audit_id + ".json")

    def get(self, audit_id: str) -> dict | None:
        with self._lock:
            if audit_id in self._cache:
                return self._cache[audit_id]
            path = self._path(audit_id)
            if not os.path.exists(path):
                return None
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self._cache[audit_id] = data
            return data

    def put(self, audit_id: str, payload: dict) -> bool:
        """冻结写入；标识已存在时返回 False（裁决不可变）。"""
        with self._lock:
            if audit_id in self._cache or os.path.exists(self._path(audit_id)):
                return False
            tmp_path = self._path(audit_id) + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, sort_keys=True,
                          indent=2)
            os.replace(tmp_path, self._path(audit_id))
            self._cache[audit_id] = payload
            return True
