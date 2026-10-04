"""撤销审计：按时间生效、幂等重放、冲突检测与求值解释。"""
from __future__ import annotations

from tests.conftest import make_token


def _three_level_chain(chain_id: str) -> dict:
    root = make_token(
        "root", None, "root", "svc-a",
        "/files/**", ["GET", "POST"], chain_id=chain_id,
    )
    mid = make_token(
        "mid", "root", "svc-a", "svc-b",
        "/files/reports/*", ["GET"], allow_ip="10.0.0.0/8", chain_id=chain_id,
    )
    leaf = make_token(
        "leaf", "mid", "svc-b", "svc-c",
        "/files/reports/q1.pdf", ["GET"], allow_ip="10.1.0.0/16",
        chain_id=chain_id,
    )
    return {"chain_id": chain_id, "tokens": [root, mid, leaf]}


def _submit(client, chain_id: str) -> None:
    resp = client.post("/api/v1/chains", json=_three_level_chain(chain_id))
    assert resp.status_code == 201, resp.text
    assert resp.json()["integrity"]["allow"] is True


def _revoke(client, chain_id: str, token_id: str, request_key: str,
            effective_at: str = "2026-06-01T00:00:00Z",
            reason: str = "密钥疑似泄露"):
    return client.post(
        f"/api/v1/chains/{chain_id}/revocations",
        json={
            "token_id": token_id,
            "effective_at": effective_at,
            "reason": reason,
            "request_key": request_key,
        },
    )


def _evaluate(client, chain_id: str, at: str):
    return client.post(
        f"/api/v1/chains/{chain_id}/evaluate",
        json={
            "request_path": "/files/reports/q1.pdf",
            "method": "GET",
            "at": at,
            "source_ip": "10.1.2.3",
        },
    )


def test_revoke_created_with_affected_in_chain_order(client):
    _submit(client, "chain-rev-1")
    resp = _revoke(client, "chain-rev-1", "mid", "ops-001")
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["replayed"] is False
    assert body["affected_token_ids"] == ["mid", "leaf"]
    event = body["event"]
    assert event["chain_id"] == "chain-rev-1"
    assert event["token_id"] == "mid"
    assert event["effective_at"] == "2026-06-01T00:00:00Z"
    assert event["reason"] == "密钥疑似泄露"
    assert event["request_key"] == "ops-001"
    assert event["created_at"]


def test_revoke_root_affects_whole_chain(client):
    _submit(client, "chain-rev-root")
    resp = _revoke(client, "chain-rev-root", "root", "ops-root")
    assert resp.status_code == 201
    assert resp.json()["affected_token_ids"] == ["root", "mid", "leaf"]


def test_revoke_replay_returns_original(client):
    _submit(client, "chain-rev-2")
    first = _revoke(client, "chain-rev-2", "mid", "ops-002")
    assert first.status_code == 201

    replay = _revoke(client, "chain-rev-2", "mid", "ops-002")
    assert replay.status_code == 200
    body = replay.json()
    assert body["replayed"] is True
    assert body["event"] == first.json()["event"]
    assert body["affected_token_ids"] == first.json()["affected_token_ids"]


def test_revoke_same_key_different_content_conflicts(client):
    _submit(client, "chain-rev-3")
    assert _revoke(client, "chain-rev-3", "mid", "ops-003").status_code == 201

    # 同一 request_key 换目标
    resp = _revoke(client, "chain-rev-3", "leaf", "ops-003")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["request_key"] == "ops-003"
    assert detail["existing_token_id"] == "mid"

    # 同一 request_key 换生效时间同样冲突
    resp = _revoke(
        client, "chain-rev-3", "mid", "ops-003",
        effective_at="2026-07-01T00:00:00Z",
    )
    assert resp.status_code == 409


def test_revoke_already_revoked_token_conflicts(client):
    _submit(client, "chain-rev-4")
    assert _revoke(client, "chain-rev-4", "mid", "ops-004a").status_code == 201

    resp = _revoke(client, "chain-rev-4", "mid", "ops-004b")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["existing_request_key"] == "ops-004a"
    assert detail["existing_token_id"] == "mid"


def test_revoke_unknown_chain_and_token_404(client):
    resp = _revoke(client, "chain-missing", "mid", "ops-005")
    assert resp.status_code == 404

    _submit(client, "chain-rev-5")
    resp = _revoke(client, "chain-rev-5", "ghost", "ops-006")
    assert resp.status_code == 404


def test_revoke_requires_timezone(client):
    _submit(client, "chain-rev-6")
    resp = _revoke(
        client, "chain-rev-6", "mid", "ops-007",
        effective_at="2026-06-01T00:00:00",
    )
    assert resp.status_code == 422


def test_evaluate_denies_revoked_node_and_descendants(client):
    _submit(client, "chain-rev-eval")
    _revoke(client, "chain-rev-eval", "mid", "ops-008")

    resp = _evaluate(client, "chain-rev-eval", "2026-07-01T00:00:00Z")
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "deny"
    # 轨迹标出最先受撤销影响的节点（被撤销节点本身）
    assert data["first_failed_node"] == "mid"
    assert data["first_failed_reason"] == "revoked"

    trace = {n["token_id"]: n for n in data["trace"]}
    assert any(c["reason"] == "revoked" for c in trace["mid"]["checks"])
    assert any(
        c["reason"] == "ancestor_revoked" for c in trace["leaf"]["checks"]
    )
    # 祖先不受影响
    assert all(c["passed"] for c in trace["root"]["checks"])


def test_evaluate_at_effective_boundary_denies(client):
    _submit(client, "chain-rev-boundary")
    _revoke(client, "chain-rev-boundary", "mid", "ops-009")

    # 请求时间不早于生效时间（含端点）即拒绝
    data = _evaluate(client, "chain-rev-boundary", "2026-06-01T00:00:00Z").json()
    assert data["decision"] == "deny"
    assert data["first_failed_reason"] == "revoked"


def test_evaluate_before_effective_uses_original_chain(client):
    _submit(client, "chain-rev-before")
    _revoke(client, "chain-rev-before", "mid", "ops-010")

    data = _evaluate(client, "chain-rev-before", "2026-05-01T00:00:00Z").json()
    assert data["decision"] == "allow"
    assert data["first_failed_node"] is None


def test_chain_get_includes_revocation_events(client):
    _submit(client, "chain-rev-get")
    _revoke(client, "chain-rev-get", "mid", "ops-011")
    _revoke(client, "chain-rev-get", "leaf", "ops-012",
            effective_at="2026-08-01T00:00:00Z", reason="例行轮换")

    got = client.get("/api/v1/chains/chain-rev-get")
    assert got.status_code == 200
    events = got.json()["revocations"]
    assert [e["request_key"] for e in events] == ["ops-011", "ops-012"]
    assert events[0]["token_id"] == "mid"
    assert events[1]["reason"] == "例行轮换"


def test_multiple_revocations_first_effective_node_wins(client):
    _submit(client, "chain-rev-multi")
    _revoke(client, "chain-rev-multi", "leaf", "ops-013",
            effective_at="2026-06-15T00:00:00Z")
    _revoke(client, "chain-rev-multi", "mid", "ops-014",
            effective_at="2026-07-01T00:00:00Z")

    # 仅 leaf 的撤销生效时：leaf 拒绝，mid 仍正常
    data = _evaluate(client, "chain-rev-multi", "2026-06-20T00:00:00Z").json()
    assert data["decision"] == "deny"
    assert data["first_failed_node"] == "leaf"
    assert data["first_failed_reason"] == "revoked"

    # mid 的撤销也生效后：链上最先受影响的节点是 mid
    data = _evaluate(client, "chain-rev-multi", "2026-07-02T00:00:00Z").json()
    assert data["decision"] == "deny"
    assert data["first_failed_node"] == "mid"
    assert data["first_failed_reason"] == "revoked"
