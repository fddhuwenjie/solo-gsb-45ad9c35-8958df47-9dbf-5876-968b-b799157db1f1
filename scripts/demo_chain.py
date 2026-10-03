"""构造并演示一条合法委托能力链：root -> service-a -> service-b。

用法：
    # 仅打印已签名的提交报文（不依赖服务运行）
    python scripts/demo_chain.py print

    # 提交到本机服务并执行一次求值（默认 http://127.0.0.1:8000）
    python scripts/demo_chain.py submit
    BASE_URL=http://localhost:8000 python scripts/demo_chain.py submit
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from app.security import compute_signature

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000")

# 与 app.database.DEMO_PRINCIPALS 保持一致的演示密钥
SECRETS = {
    "root": os.getenv("ROOT_HMAC_SECRET", "dev-root-secret-change-me"),
    "service-a": "demo-secret-service-a",
    "service-b": "demo-secret-service-b",
}

CHAIN_ID = os.getenv("DEMO_CHAIN_ID", "demo-chain-0001")


def _token(
    token_id: str,
    parent_id: str | None,
    issuer: str,
    subject: str,
    path_pattern: str,
    methods: list[str],
    not_before: datetime,
    not_after: datetime,
    allow_ip: str | None,
) -> dict:
    t = {
        "token_id": token_id,
        "parent_id": parent_id,
        "chain_id": CHAIN_ID,
        "issuer": issuer,
        "subject": subject,
        "path_pattern": path_pattern,
        "methods": methods,
        "not_before": not_before.isoformat().replace("+00:00", "Z"),
        "not_after": not_after.isoformat().replace("+00:00", "Z"),
        "allow_ip": allow_ip,
        "signature": "",
    }
    t["signature"] = compute_signature(t, SECRETS[issuer])
    return t


def build_submission() -> dict:
    now = datetime.now(timezone.utc)
    nb = now - timedelta(days=1)
    na = now + timedelta(days=30)
    root = _token(
        "token-root",
        None,
        "root",
        "service-a",
        "/files/**",
        ["GET", "POST", "PUT"],
        nb,
        na,
        None,
    )
    delegated_a = _token(
        "token-a",
        "token-root",
        "service-a",
        "service-b",
        "/files/reports/**",
        ["GET", "POST"],
        nb + timedelta(hours=1),
        na - timedelta(days=1),
        "10.0.0.0/8",
    )
    delegated_b = _token(
        "token-b",
        "token-a",
        "service-b",
        "service-b-worker",
        "/files/reports/2026/q1.pdf",
        ["GET"],
        nb + timedelta(days=1),
        na - timedelta(days=2),
        "10.1.0.0/16",
    )
    return {"chain_id": CHAIN_ID, "tokens": [root, delegated_a, delegated_b]}


def build_evaluation() -> dict:
    return {
        "request_path": "/files/reports/2026/q1.pdf",
        "method": "GET",
        "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_ip": "10.1.2.3",
        "body": {"q": "demo"},
    }


def _post(url: str, payload: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "print"
    submission = build_submission()
    if mode == "print":
        print(json.dumps(submission, ensure_ascii=False, indent=2))
        return 0

    if mode != "submit":
        print(__doc__)
        return 2

    status_code, body = _post(f"{BASE_URL}/api/v1/chains", submission)
    print(f"[submit] HTTP {status_code}")
    print(json.dumps(body, ensure_ascii=False, indent=2))

    # 幂等重放：同样内容再来一次
    status_code, body = _post(f"{BASE_URL}/api/v1/chains", submission)
    print(f"[replay] HTTP {status_code} (replayed={body.get('replayed')})")

    status_code, body = _post(
        f"{BASE_URL}/api/v1/chains/{CHAIN_ID}/evaluate", build_evaluation()
    )
    print(f"[evaluate] HTTP {status_code}")
    print(json.dumps(body, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
