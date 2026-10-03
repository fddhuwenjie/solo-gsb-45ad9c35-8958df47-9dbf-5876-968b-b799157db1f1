"""能力链验证引擎：结构完整性、HMAC 验签、逐级收窄与请求级判定。"""
from __future__ import annotations

from collections import defaultdict
from typing import Callable

from .config import settings
from .models import (
    CapabilityToken,
    ChainSubmission,
    Check,
    EvaluateRequest,
    EvaluateResult,
    IntegrityReport,
    NodeTrace,
)
from .security import (
    ip_in_network,
    ip_range_narrows,
    methods_narrow,
    pattern_covers,
    request_path_matches,
    sha256_hex,
    canonical_json,
    time_window_narrows,
    verify_signature,
)

SecretLookup = Callable[[str], str | None]


class _TraceBuilder:
    def __init__(self, token: CapabilityToken, is_root: bool) -> None:
        self.token = token
        self.is_root = is_root
        self.checks: list[Check] = []

    def add(self, check: Check) -> None:
        self.checks.append(check)

    def build(self) -> NodeTrace:
        return NodeTrace(
            token_id=self.token.token_id,
            issuer=self.token.issuer,
            subject=self.token.subject,
            parent_id=self.token.parent_id,
            is_root=self.is_root,
            checks=self.checks,
        )


def validate_chain(
    submission: ChainSubmission, secret_lookup: SecretLookup
) -> tuple[IntegrityReport, list[CapabilityToken]]:
    """执行提交时的完整性验证，返回报告与根出发的有序令牌。"""
    tokens = submission.tokens
    builders: dict[str, _TraceBuilder] = {}
    for t in tokens:
        builders.setdefault(
            t.token_id, _TraceBuilder(t, is_root=t.parent_id is None)
        )

    unique_tokens: dict[str, CapabilityToken] = {}
    duplicate_seen: set[str] = set()

    # ---- 阶段 0a：重复 id -------------------------------------------------
    for pos, t in enumerate(tokens):
        if t.token_id in unique_tokens:
            duplicate_seen.add(t.token_id)
            builders[t.token_id].add(
                Check(
                    name="unique_id",
                    passed=False,
                    detail=f"token_id 在提交中重复出现（位置 {pos}）",
                    reason="duplicate_id",
                )
            )
        else:
            unique_tokens[t.token_id] = t

    # ---- 阶段 0b：根授权 --------------------------------------------------
    roots = [t for t in unique_tokens.values() if t.parent_id is None]
    if not roots:
        first = tokens[0]
        builders[first.token_id].add(
            Check(
                name="root_authority",
                passed=False,
                detail="链中缺少根授权（parent_id 为 null 的令牌）",
                reason="missing_root",
            )
        )
    for idx, root in enumerate(roots):
        b = builders[root.token_id]
        if idx == 0:
            b.add(Check(name="root_authority", passed=True, detail="根授权存在且唯一"))
        else:
            b.add(
                Check(
                    name="root_authority",
                    passed=False,
                    detail=f"存在多个根授权（{root.token_id}）",
                    reason="multiple_roots",
                )
            )

    # ---- 阶段 0c：断链 ----------------------------------------------------
    for t in unique_tokens.values():
        if t.parent_id is not None and t.parent_id not in unique_tokens:
            builders[t.token_id].add(
                Check(
                    name="chain_link",
                    passed=False,
                    detail=f"父令牌 {t.parent_id} 不存在",
                    reason="broken_link",
                )
            )

    # ---- 阶段 0d：分叉（每个父令牌至多一个子令牌） -------------------------
    children: dict[str, list[CapabilityToken]] = defaultdict(list)
    for t in unique_tokens.values():
        if t.parent_id is not None and t.parent_id in unique_tokens:
            children[t.parent_id].append(t)
    for kids in children.values():
        for extra in kids[1:]:
            builders[extra.token_id].add(
                Check(
                    name="single_child",
                    passed=False,
                    detail=(
                        f"父令牌 {extra.parent_id} 已被另一个令牌引用，"
                        "能力链不允许分叉"
                    ),
                    reason="branch",
                )
            )

    # ---- 阶段 0e：环检测（沿 parent_id 上行） -----------------------------
    cycle_nodes: set[str] = set()
    for start in unique_tokens:
        path: list[str] = []
        seen_local: set[str] = set()
        cur: str | None = start
        while cur is not None and cur in unique_tokens:
            if cur in seen_local:
                # 找到环：从 cur 再次出现处开始收集
                loop_start = path.index(cur)
                cycle_nodes.update(path[loop_start:])
                break
            seen_local.add(cur)
            path.append(cur)
            cur = unique_tokens[cur].parent_id
    for cid in cycle_nodes:
        builders[cid].add(
            Check(
                name="acyclic",
                passed=False,
                detail="沿 parent_id 检测到委托环",
                reason="cycle",
            )
        )

    # ---- 从根出发的链顺序（首个子令牌优先，环保护） -----------------------
    order: list[CapabilityToken] = []
    if roots:
        chosen_root = roots[0]
        cur: CapabilityToken | None = chosen_root
        guard: set[str] = set()
        while cur is not None and cur.token_id not in guard:
            guard.add(cur.token_id)
            order.append(cur)
            kids = children.get(cur.token_id, [])
            cur = kids[0] if kids else None

    ordered_ids = {t.token_id for t in order}

    # ---- 阶段 0f：与根不相连的孤点 ----------------------------------------
    if roots:
        for t in unique_tokens.values():
            if t.token_id not in ordered_ids:
                builders[t.token_id].add(
                    Check(
                        name="root_reachable",
                        passed=False,
                        detail="令牌无法从根授权沿 parent_id 到达",
                        reason="disconnected",
                    )
                )

    # ---- 阶段 1：签名 / 签发者 / 逐级收窄 ---------------------------------
    by_id = unique_tokens
    for t in order:
        b = builders[t.token_id]
        secret = secret_lookup(t.issuer)
        if secret is None:
            b.add(
                Check(
                    name="signature",
                    passed=False,
                    detail=f"签发者 {t.issuer} 未注册，无法取得 HMAC 密钥",
                    reason="unknown_issuer",
                )
            )
        else:
            ok = verify_signature(t, secret)
            b.add(
                Check(
                    name="signature",
                    passed=ok,
                    detail=(
                        "HMAC-SHA256 验签通过"
                        if ok
                        else "HMAC-SHA256 签名与规范化报文不符"
                    ),
                    reason=None if ok else "bad_signature",
                )
            )

        if t.parent_id is None:
            root_ok = t.issuer == settings.root_principal
            b.add(
                Check(
                    name="root_issuer",
                    passed=root_ok,
                    detail=(
                        f"根授权由配置的根主体 {settings.root_principal!r} 签发"
                        if root_ok
                        else f"根授权签发者 {t.issuer!r} 不是配置的根主体 "
                        f"{settings.root_principal!r}"
                    ),
                    reason=None if root_ok else "issuer_mismatch",
                )
            )
            continue

        parent = by_id.get(t.parent_id)
        if parent is None:
            continue  # 断链已在阶段 0c 记录

        issuer_ok = t.issuer == parent.subject
        b.add(
            Check(
                name="issuer_chain",
                passed=issuer_ok,
                detail=(
                    f"签发者 {t.issuer} 即父令牌主体 {parent.subject}"
                    if issuer_ok
                    else f"签发者 {t.issuer} 不是父令牌 {parent.token_id} "
                    f"的主体 {parent.subject}"
                ),
                reason=None if issuer_ok else "issuer_mismatch",
            )
        )

        path_ok = pattern_covers(t.path_pattern, parent.path_pattern)
        b.add(
            Check(
                name="path_narrows",
                passed=path_ok,
                detail=(
                    f"{t.path_pattern} 收窄自 {parent.path_pattern}"
                    if path_ok
                    else f"子路径 {t.path_pattern} 超出父路径 "
                    f"{parent.path_pattern} 的允许范围"
                ),
                reason=None if path_ok else "path_widens",
            )
        )

        method_ok = methods_narrow(set(t.methods), set(parent.methods))
        b.add(
            Check(
                name="methods_narrow",
                passed=method_ok,
                detail=(
                    f"方法集合 {sorted(t.methods)} ⊆ {sorted(parent.methods)}"
                    if method_ok
                    else f"方法集合 {sorted(t.methods)} 不是父集合 "
                    f"{sorted(parent.methods)} 的子集"
                ),
                reason=None if method_ok else "method_widens",
            )
        )

        time_ok = time_window_narrows(
            t.not_before, t.not_after, parent.not_before, parent.not_after
        )
        b.add(
            Check(
                name="time_window_narrows",
                passed=time_ok,
                detail=(
                    "时间窗包含于父令牌时间窗"
                    if time_ok
                    else f"时间窗 [{t.not_before.isoformat()}, "
                    f"{t.not_after.isoformat()}] 超出父令牌时间窗"
                ),
                reason=None if time_ok else "time_window_widens",
            )
        )

        ip_ok = ip_range_narrows(t.allow_ip, parent.allow_ip)
        child_desc = t.allow_ip or "(无限制)"
        parent_desc = parent.allow_ip or "(无限制)"
        b.add(
            Check(
                name="ip_range_narrows",
                passed=ip_ok,
                detail=(
                    f"IP 网段 {child_desc} 收窄自 {parent_desc}"
                    if ip_ok
                    else f"IP 网段 {child_desc} 相对父网段 {parent_desc} 构成放大"
                ),
                reason=None if ip_ok else "ip_widens",
            )
        )

    report = _build_report(builders, order, tokens)
    return report, order


def _build_report(
    builders: dict[str, _TraceBuilder],
    order: list[CapabilityToken],
    submitted: list[CapabilityToken],
) -> IntegrityReport:
    trace_order: list[_TraceBuilder] = [builders[t.token_id] for t in order]
    seen = {b.token.token_id for b in trace_order}
    for t in submitted:
        if t.token_id not in seen:
            trace_order.append(builders[t.token_id])
            seen.add(t.token_id)

    traces = [b.build() for b in trace_order]
    first_node, first_reason = _first_failure(traces)
    allow = first_node is None and bool(traces)
    return IntegrityReport(
        allow=allow,
        first_failed_node=first_node,
        first_failed_reason=first_reason,
        ordered_token_ids=[t.token_id for t in order],
        trace=traces,
    )


def _first_failure(traces: list[NodeTrace]) -> tuple[str | None, str | None]:
    for node in traces:
        for check in node.checks:
            if not check.passed:
                return node.token_id, check.reason
    return None, None


def evaluate_request(
    submission: ChainSubmission,
    request: EvaluateRequest,
    secret_lookup: SecretLookup,
) -> EvaluateResult:
    """对已存能力链执行请求级判定（完整性检查会重新计算一遍）。"""
    integrity, order = validate_chain(submission, secret_lookup)
    builders: dict[str, _TraceBuilder] = {
        n.token_id: _TraceBuilder(
            next(t for t in submission.tokens if t.token_id == n.token_id),
            is_root=False,
        )
        for n in integrity.trace
    }
    # 把已生成的检查搬入 builder，再追加请求级检查
    for node in integrity.trace:
        builders[node.token_id].is_root = node.is_root
        builders[node.token_id].checks = list(node.checks)

    at = request.at
    for t in order:
        b = builders[t.token_id]

        if at < t.not_before:
            b.add(
                Check(
                    name="time_valid",
                    passed=False,
                    detail=f"请求时间 {at.isoformat()} 早于生效时间 {t.not_before.isoformat()}",
                    reason="before_not_before",
                )
            )
        elif at > t.not_after:
            b.add(
                Check(
                    name="time_valid",
                    passed=False,
                    detail=f"请求时间 {at.isoformat()} 晚于失效时间 {t.not_after.isoformat()}",
                    reason="after_not_after",
                )
            )
        else:
            b.add(
                Check(name="time_valid", passed=True, detail="请求时间位于令牌有效期内")
            )

        method_ok = request.method in t.methods
        b.add(
            Check(
                name="method_allowed",
                passed=method_ok,
                detail=(
                    f"方法 {request.method} 被允许"
                    if method_ok
                    else f"方法 {request.method} 不在 {sorted(t.methods)} 中"
                ),
                reason=None if method_ok else "method_not_allowed",
            )
        )

        path_ok = request_path_matches(t.path_pattern, request.request_path)
        b.add(
            Check(
                name="path_covered",
                passed=path_ok,
                detail=(
                    f"{request.request_path} 匹配 {t.path_pattern}"
                    if path_ok
                    else f"{request.request_path} 不匹配模式 {t.path_pattern}"
                ),
                reason=None if path_ok else "path_not_covered",
            )
        )

        if t.allow_ip is not None:
            if request.source_ip is None:
                ip_ok = False
                detail = f"令牌限定 {t.allow_ip}，但请求未提供 source_ip"
            else:
                ip_ok = ip_in_network(request.source_ip, t.allow_ip)
                detail = (
                    f"{request.source_ip} 位于 {t.allow_ip}"
                    if ip_ok
                    else f"{request.source_ip} 不在 {t.allow_ip} 内"
                )
            b.add(
                Check(
                    name="ip_allowed",
                    passed=ip_ok,
                    detail=detail,
                    reason=None if ip_ok else "ip_not_allowed",
                )
            )
        else:
            b.add(Check(name="ip_allowed", passed=True, detail="令牌未限制来源 IP"))

    # 重新按完整性轨迹顺序组装
    traces: list[NodeTrace] = []
    for node in integrity.trace:
        traces.append(builders[node.token_id].build())
    first_node, first_reason = _first_failure(traces)
    decision = "allow" if first_node is None and traces else "deny"
    body_sha = sha256_hex(canonical_json(request.body).encode("utf-8"))
    return EvaluateResult(
        chain_id=submission.chain_id,
        decision=decision,  # type: ignore[arg-type]
        first_failed_node=first_node,
        first_failed_reason=first_reason,
        body_sha256=body_sha,
        trace=traces,
    )
