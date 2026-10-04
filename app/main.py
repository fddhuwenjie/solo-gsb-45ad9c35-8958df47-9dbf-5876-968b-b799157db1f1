"""FastAPI 应用：提交能力链、幂等重放、冲突检测、请求级判定与撤销审计。"""
from __future__ import annotations

import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse

from .database import (
    get_conn,
    get_db,
    get_revocation,
    get_secret,
    get_token_revocation,
    init_db,
    load_affected_token_ids,
    load_chain_record,
    load_revocations,
    load_submission,
    save_chain,
    save_revocation,
    upsert_principal,
)
from .engine import evaluate_request, validate_chain
from .models import (
    ChainRecord,
    ChainSubmission,
    ConflictDetail,
    EvaluateRequest,
    EvaluateResult,
    PrincipalIn,
    PrincipalOut,
    RevocationConflictDetail,
    RevocationEvent,
    RevocationRequest,
    RevocationResult,
    SubmissionResult,
)
from .security import canonical_submission_hash

@asynccontextmanager
async def lifespan(app: FastAPI):
    with get_conn() as conn:
        init_db(conn)
    yield


app = FastAPI(
    title="委托能力链验证 API",
    description=(
        "客户端提交根授权和以 parent_id 相连的委托令牌；服务验签、检测断链与环，"
        "并强制路径 / 方法 / 时间窗 / IP 网段只能逐级收窄。"
    ),
    version="1.0.0",
    lifespan=lifespan,
)


def _secret_lookup(conn: sqlite3.Connection):
    return lambda name: get_secret(conn, name)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/principals", response_model=PrincipalOut, status_code=201)
def register_principal(
    payload: PrincipalIn, conn: sqlite3.Connection = Depends(get_db)
) -> PrincipalOut:
    """注册一个签发主体及其 HMAC 密钥（演示 / 运维引导用）。"""
    try:
        created = upsert_principal(conn, payload.name, payload.hmac_secret)
    except sqlite3.IntegrityError:
        created = False
    if not created:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"主体 {payload.name!r} 已存在",
        )
    return PrincipalOut(name=payload.name)


@app.post(
    "/api/v1/chains",
    response_model=SubmissionResult,
    responses={409: {"model": ConflictDetail}},
    status_code=201,
)
def submit_chain(
    submission: ChainSubmission,
    conn: sqlite3.Connection = Depends(get_db),
) -> JSONResponse:
    """提交（或重放）一条能力链。

    - 相同 chain_id 且内容完全一致：幂等返回 200，``replayed=true``；
    - 相同 chain_id 但内容变化：返回 409 冲突；
    - 新 chain_id：持久化并返回 201。完整性失败也会持久化（含失败轨迹）。
    """
    received_hash = canonical_submission_hash(
        submission.chain_id, submission.tokens
    )
    existing_hash = _existing_hash(conn, submission.chain_id)

    report, _ = validate_chain(submission, _secret_lookup(conn))

    if existing_hash is not None:
        if existing_hash == received_hash:
            result = SubmissionResult(
                chain_id=submission.chain_id, replayed=True, integrity=report
            )
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=result.model_dump(mode="json"),
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"chain_id={submission.chain_id!r} 已存在但内容不同；"
                    "相同 chain_id 不允许提交不同内容"
                ),
                "chain_id": submission.chain_id,
                "existing_sha256": existing_hash,
                "received_sha256": received_hash,
            },
        )

    save_chain(conn, submission, received_hash, report)
    result = SubmissionResult(
        chain_id=submission.chain_id, replayed=False, integrity=report
    )
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=result.model_dump(mode="json"),
    )


def _existing_hash(conn: sqlite3.Connection, chain_id: str) -> str | None:
    row = conn.execute(
        "SELECT content_sha256 FROM chains WHERE chain_id = ?", (chain_id,)
    ).fetchone()
    return row["content_sha256"] if row else None


@app.get("/api/v1/chains/{chain_id}", response_model=ChainRecord)
def get_chain(
    chain_id: str, conn: sqlite3.Connection = Depends(get_db)
) -> dict:
    record = load_chain_record(conn, chain_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"chain_id {chain_id!r} 不存在")
    return record


@app.post("/api/v1/chains/{chain_id}/evaluate", response_model=EvaluateResult)
def evaluate_chain(
    chain_id: str,
    payload: EvaluateRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> EvaluateResult:
    submission = load_submission(conn, chain_id)
    if submission is None:
        raise HTTPException(status_code=404, detail=f"chain_id {chain_id!r} 不存在")
    revocations = load_revocations(conn, chain_id)
    return evaluate_request(submission, payload, _secret_lookup(conn), revocations)


@app.post(
    "/api/v1/chains/{chain_id}/revocations",
    response_model=RevocationResult,
    responses={409: {"model": RevocationConflictDetail}},
    status_code=201,
)
def revoke_token(
    chain_id: str,
    payload: RevocationRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> JSONResponse:
    """提交（或重放）一条按时间生效的撤销事件。

    - 同一 request_key 且内容一致：幂等返回 200，``replayed=true``，结果与首次相同；
    - 同一 request_key 但内容不同（换目标等）：返回 409 冲突；
    - 令牌已被其它 request_key 撤销：返回 409（已撤销令牌不得重复生效）；
    - 新 request_key：在同一事务中确认令牌存在并追加不可变事件，返回 201
      以及按原链顺序（根→叶）列出的受影响令牌（被撤销节点及其后代）。
    """
    submission = load_submission(conn, chain_id)
    if submission is None:
        raise HTTPException(status_code=404, detail=f"chain_id {chain_id!r} 不存在")
    if payload.token_id not in {t.token_id for t in submission.tokens}:
        raise HTTPException(
            status_code=404,
            detail=f"令牌 {payload.token_id!r} 不存在于链 {chain_id!r}",
        )

    existing = get_revocation(conn, chain_id, payload.request_key)
    if existing is not None:
        same = (
            existing.token_id == payload.token_id
            and existing.effective_at == payload.effective_at
            and existing.reason == payload.reason
        )
        if same:
            result = RevocationResult(
                chain_id=chain_id,
                replayed=True,
                event=existing,
                affected_token_ids=load_affected_token_ids(
                    conn, chain_id, payload.request_key
                ),
            )
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=result.model_dump(mode="json"),
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"request_key={payload.request_key!r} 已用于链 {chain_id!r} "
                    "的另一条撤销事件；相同 request_key 不允许携带不同内容"
                ),
                "chain_id": chain_id,
                "request_key": payload.request_key,
                "existing_request_key": existing.request_key,
                "existing_token_id": existing.token_id,
            },
        )

    prior = get_token_revocation(conn, chain_id, payload.token_id)
    if prior is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"令牌 {payload.token_id!r} 已被 request_key="
                    f"{prior.request_key!r} 的撤销事件吊销；已撤销令牌不得重复生效"
                ),
                "chain_id": chain_id,
                "request_key": payload.request_key,
                "existing_request_key": prior.request_key,
                "existing_token_id": prior.token_id,
            },
        )

    affected = _affected_token_ids(conn, submission, payload.token_id)
    event = RevocationEvent(
        chain_id=chain_id,
        token_id=payload.token_id,
        effective_at=payload.effective_at,
        reason=payload.reason,
        request_key=payload.request_key,
        created_at=datetime.now(timezone.utc),
    )
    try:
        save_revocation(conn, event, affected)
    except sqlite3.IntegrityError:
        # 并发下同 request_key / 同 token 的重复插入
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": "撤销事件与既有记录冲突",
                "chain_id": chain_id,
                "request_key": payload.request_key,
                "existing_request_key": None,
                "existing_token_id": None,
            },
        )
    result = RevocationResult(
        chain_id=chain_id, replayed=False, event=event, affected_token_ids=affected
    )
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=result.model_dump(mode="json"),
    )


def _affected_token_ids(
    conn: sqlite3.Connection, submission: ChainSubmission, token_id: str
) -> list[str]:
    """被撤销节点及其后代，按原链顺序（根→叶）。"""
    _, order = validate_chain(submission, _secret_lookup(conn))
    ids = [t.token_id for t in order]
    if token_id in ids:
        return ids[ids.index(token_id):]
    return [token_id]
