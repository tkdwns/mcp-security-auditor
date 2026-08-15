"""감사 실행 서비스 — API 계층과 판별 파이프라인 사이의 어댑터.

API 는 도구 정의를 받고, 판별 파이프라인은 내부 dict 형식을 쓴다.
그 변환과 결과 정리를 여기서 담당해 main.py 를 얇게 유지한다.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG_FILE = ROOT / "data" / "catalog" / "trusted_tools.json"

MODEL_DEFAULT = "claude-sonnet-5"


def _bootstrap_env() -> None:
    """앱 기동 시 .env 를 환경변수로 로드한다.

    CLI 진입점들은 각자 load_env() 를 호출했지만, uvicorn 으로 앱을 띄울 때는
    아무도 호출하지 않아 ANTHROPIC_API_KEY 가 비어 있었다(503 응답).
    여기서 한 번 로드해 CLI 와 API 의 동작을 일치시킨다.

    운영 환경(Render 등)에서는 .env 파일이 없고 플랫폼이 환경변수를 주입한다.
    load_env 는 setdefault 를 쓰므로 **플랫폼 환경변수가 항상 우선**한다.
    파일이 없으면 조용히 넘어간다.
    """
    try:
        from analyzer.run import load_env
        load_env(ROOT)
    except Exception:  # noqa: BLE001 — 부팅을 막지 않는다
        pass


_bootstrap_env()


def load_catalog() -> set[str]:
    """내장 신뢰 카탈로그.

    data/raw/ 는 .gitignore 대상이라 컨테이너에 포함되지 않는다.
    배포에 필요한 도구명 목록만 data/catalog/ 에 커밋해 두고 여기서 읽는다.
    """
    if CATALOG_FILE.exists():
        d = json.loads(CATALOG_FILE.read_text(encoding="utf-8"))
        return set(d.get("tool_names", []))
    return set()


def llm_available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def to_internal(server_name: str, tools) -> list[dict]:
    """API 입력(ToolDefinitionIn) → 파이프라인 내부 형식."""
    return [{
        "sample_id": f"{server_name}::{t.name}",
        "source_server": server_name,
        "tool_name": t.name,
        "description": t.description,
        "input_schema": t.inputSchema or {},
    } for t in tools]


def run_audit(server_name: str, tools: list[dict], catalog: set[str],
              model: str | None = None, on_progress=None) -> dict:
    """판별 파이프라인 실행 후 API 응답 형태로 정리.

    무거운 import 는 함수 안에서 한다. 앱 기동 시점에 anthropic 클라이언트까지
    끌어오면 콜드 스타트가 길어지는데, Render 무료 플랜은 15분 유휴 후 슬립되므로
    콜드 스타트가 실제 사용자 경험에 직접 반영된다.
    """
    from analyzer.llm_judge import LLMJudge, verify_evidence
    from analyzer.rules import evaluate_sample
    from experiments.strategies import make_catalog_strategy
    from report.severity import SEVERITY_ORDER, assess, overall_grade, owasp_label
    import time

    model = model or os.environ.get("ANTHROPIC_MODEL", MODEL_DEFAULT)
    judge = LLMJudge(model=model, call_cap=len(tools) + 5)
    strat = make_catalog_strategy(catalog)

    findings, notes, safe, verdicts = [], [], [], []
    t0 = time.time()

    for i, t in enumerate(tools, 1):
        if on_progress:
            on_progress(i, len(tools), t["tool_name"])
        rule = evaluate_sample(t, catalog)
        v = judge.judge(t, strategy=strat)
        verdicts.append(v)
        if v.error:
            continue

        if v.is_malicious:
            detected_by = "both" if rule.rule_flag else "llm"
        elif rule.rule_flag:
            # 규칙만 반응: 위험 목록과 종합 판정에서 제외하고 참고로만 기록.
            # (홀드아웃 v2 에서 규칙의 고유 탐지 기여도는 0으로 측정되었고,
            #  정상 서버에 오탐을 만들어 판정을 왜곡했다.)
            notes.append({"tool_name": t["tool_name"],
                          "rule_signals": [h.rule_id for h in rule.hits],
                          "details": [h.detail for h in rule.hits]})
            safe.append(t["tool_name"])
            continue
        else:
            safe.append(t["tool_name"])
            continue

        level, action = assess(v.attack_type, v.confidence, detected_by)
        findings.append({
            "tool_name": t["tool_name"], "severity": level,
            "owasp": owasp_label(v.owasp_code), "attack_type": v.attack_type,
            "confidence": round(v.confidence, 2), "detected_by": detected_by,
            "evidence": v.evidence_span, "reasoning": v.reasoning, "action": action,
            "evidence_verified": verify_evidence(
                v.evidence_span, t.get("description"), t.get("input_schema")),
        })

    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), -f["confidence"]))
    counts = dict(Counter(f["severity"] for f in findings))
    grade, verdict = overall_grade(counts)
    cost = judge.cost_krw(verdicts)

    return {
        "server_name": server_name, "model": model, "n_tools": len(tools),
        "grade": grade, "verdict": verdict, "severity_counts": counts,
        "findings": findings, "notes": notes, "safe_tools": safe,
        "elapsed_sec": round(time.time() - t0, 1),
        "cost_krw": cost["krw"],
    }
