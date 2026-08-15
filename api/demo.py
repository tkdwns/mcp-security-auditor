"""데모 결과 제공.

왜 필요한가
-----------
채용 담당자가 링크를 눌렀을 때 **API 키 없이, 비용 없이** 결과를 볼 수 있어야
한다. 실제로 가장 많이 눌릴 버튼이다. 3주차에 생성해 저장소에 커밋한 리포트를
정적으로 서빙한다. LLM 호출이 일어나지 않으므로 비용은 0이고, 예산이 소진된
상황의 폴백 경로로도 쓰인다(Step 3).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"

DEMO_KINDS = {
    "clean": "demo-clean-server",
    "poisoned": "demo-malicious-server",
    "mixed": "demo-mixed-server",
}


def _latest(prefix: str, suffix: str) -> Path | None:
    if not REPORTS.exists():
        return None
    cands = sorted(REPORTS.glob(f"{prefix}_*{suffix}"))
    return cands[-1] if cands else None


def available() -> list[str]:
    return [k for k, p in DEMO_KINDS.items() if _latest(p, ".json")]


def load(kind: str) -> dict[str, Any] | None:
    prefix = DEMO_KINDS.get(kind)
    if not prefix:
        return None
    f = _latest(prefix, ".json")
    if not f:
        return None
    d = json.loads(f.read_text(encoding="utf-8"))
    d["_demo"] = True
    d["_source_file"] = f.name
    return d


def load_markdown(kind: str) -> str | None:
    prefix = DEMO_KINDS.get(kind)
    if not prefix:
        return None
    f = _latest(prefix, ".md")
    return f.read_text(encoding="utf-8") if f else None


def as_audit_result(kind: str, notice: str | None = None) -> dict | None:
    """데모 리포트를 AuditResult 스키마로 변환한다.

    예산 소진 시 폴백 응답으로 쓰기 위한 것이다. 클라이언트 입장에서는
    평소와 동일한 형태의 결과를 받으므로 폴링 흐름을 바꿀 필요가 없다.
    """
    d = load(kind)
    if d is None:
        return None
    from collections import Counter
    findings = []
    for f in d.get("findings", []):
        findings.append({
            "tool_name": f.get("tool_name", ""),
            "severity": f.get("severity", "Info"),
            "owasp": f.get("owasp", ""),
            "attack_type": f.get("attack_type", "none"),
            "confidence": float(f.get("confidence", 0.0)),
            "detected_by": f.get("detected_by", "llm"),
            "evidence": f.get("evidence", "") or "",
            "evidence_verified": f.get("evidence_verified"),
            "reasoning": f.get("reasoning", "") or "",
            "action": f.get("action", "") or "",
        })
    counts = dict(Counter(f["severity"] for f in findings))
    try:
        from report.severity import overall_grade
        grade, verdict = overall_grade(counts)
    except Exception:  # noqa: BLE001
        grade, verdict = ("위험 (Blocked)" if counts else "적합 (Pass)"), ""
    return {
        "server_name": d.get("server", kind),
        "model": d.get("model", "claude-sonnet-5"),
        "n_tools": d.get("n_tools", len(findings) + len(d.get("safe", []))),
        "grade": grade,
        "verdict": (notice + " " + verdict).strip() if notice else verdict,
        "severity_counts": counts,
        "findings": findings,
        "notes": [],
        "safe_tools": [s.get("tool_name", "") for s in d.get("safe", [])],
        "elapsed_sec": float(d.get("elapsed_sec", 0.0)),
        "cost_krw": 0.0,   # 폴백은 LLM 을 호출하지 않았으므로 비용 0
    }
