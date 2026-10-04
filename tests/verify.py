"""Compose verify 入口：一次运行完成 代码测试 + 构建检查 + API/HTTP 冒烟。

依次执行：
  1. 代码测试  —— unittest 全量单元测试
  2. 构建检查  —— compileall 字节码编译 + 关键模块导入检查
  3. API/HTTP 冒烟 —— 等待健康响应后对运行中的服务执行 tests.smoke

全部通过则以退出码 0 结束，否则以退出码 1 报告失败。
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
import urllib.request


def _run_step(name: str, argv: list[str]) -> bool:
    print(f"\n=== {name} ===", flush=True)
    proc = subprocess.run(argv)
    print(f"--- {name}: {'OK' if proc.returncode == 0 else 'FAILED'}",
          flush=True)
    return proc.returncode == 0


def _wait_for_health(base_url: str, attempts: int = 60) -> bool:
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=2) as r:
                if r.status == 200:
                    return True
        except OSError:
            pass
        time.sleep(1)
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://app:8080")
    parser.add_argument("--skip-smoke", action="store_true")
    args = parser.parse_args()

    failures: list[str] = []

    if not _run_step("代码测试 (unittest)",
                     [sys.executable, "-m", "unittest", "discover",
                      "-s", "tests", "-t", ".", "-v"]):
        failures.append("unit-tests")

    if not _run_step("构建检查 (compileall)",
                     [sys.executable, "-m", "compileall", "-q", "app", "tests"]):
        failures.append("compileall")
    if not _run_step("构建检查 (import)",
                     [sys.executable, "-c",
                      "import app.server, app.audit, app.sctp, "
                      "app.crc32c, app.store"]):
        failures.append("import-check")

    if not args.skip_smoke:
        print("\n=== API/HTTP 冒烟 ===", flush=True)
        if not _wait_for_health(args.base_url):
            print(f"等待 {args.base_url} 健康响应超时", flush=True)
            failures.append("health-timeout")
        else:
            from tests.smoke import run as smoke_run
            smoke_failures = smoke_run(args.base_url)
            if smoke_failures:
                failures.extend(smoke_failures)
            print(f"--- 冒烟: {'OK' if not smoke_failures else 'FAILED'}",
                  flush=True)

    print("\n=== verify 汇总 ===", flush=True)
    if failures:
        print(f"VERIFY FAILED: {failures}", flush=True)
        return 1
    print("VERIFY OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
