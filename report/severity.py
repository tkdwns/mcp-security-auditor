"""심각도 산정 규칙.

설계 원칙
---------
1. 심각도는 '공격 유형'과 '모델 확신도'의 조합으로 정한다.
   같은 유형이라도 확신이 낮으면 한 단계 낮춘다. 확신 없는 Critical 은
   담당자의 신뢰를 잃게 만든다.
2. 규칙 엔진만 탐지하고 LLM 은 정상이라 본 건은 Low(검토 필요)로 둔다.
   3주차 실험에서 규칙 단독 정밀도는 낮았으므로 단정하지 않는다.
3. 각 등급에 '조치 권고'를 반드시 붙인다. 등급만 주고 끝내면 실무에서 쓸 수 없다.
"""

from __future__ import annotations

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

# 유형별 기본 등급과, 확신도가 이 값 미만이면 한 단계 강등
_BASE = {
    "hidden_instruction": ("Critical", 0.85),
    "tool_shadowing": ("High", 0.75),
    "scope_creep": ("High", 0.85),
    "schema_mismatch": ("Medium", 0.70),
}

_ACTION = {
    "hidden_instruction":
        "도입 즉시 보류. 서버 배포자에게 해당 문구의 출처를 확인하고, "
        "에이전트가 이 서버에 연결된 이력이 있다면 자격증명 노출 여부를 점검할 것.",
    "tool_shadowing":
        "동일/유사 이름의 기존 도구와 충돌 여부를 확인. 정당한 대체 구현인지 "
        "배포자에게 확인하고, 아니라면 허용목록에서 제외할 것.",
    "scope_creep":
        "도구의 선언된 목적에 필요한 최소 권한만 부여하도록 설정을 조정. "
        "샌드박스 경로/네트워크 접근 범위를 명시적으로 제한할 것.",
    "schema_mismatch":
        "설명문에 근거가 없는 파라미터가 실제로 어떤 값을 전달받는지 확인. "
        "필요 없다면 스키마에서 제거를 요청할 것.",
}

_OWASP_NAME = {
    "MCP02": "권한 상승 (Scope Creep)",
    "MCP03": "도구 중독 (Tool Poisoning)",
    "MCP06": "의도 흐름 전복 (Prompt Injection)",
    "MCP10": "컨텍스트 주입 및 과다 공유",
    "NONE": "-",
}


def downgrade(level: str) -> str:
    i = SEVERITY_ORDER.index(level)
    return SEVERITY_ORDER[min(i + 1, len(SEVERITY_ORDER) - 1)]


def assess(attack_type: str, confidence: float, detected_by: str) -> tuple[str, str]:
    """(심각도, 조치권고) 반환.

    detected_by: 'llm' | 'rule' | 'both'
    """
    if detected_by == "rule":
        return "Low", (
            "정적 규칙만 탐지하고 LLM 판별기는 정상으로 보았습니다. "
            "오탐 가능성이 있으니 담당자가 원문을 직접 확인하세요."
        )
    base, threshold = _BASE.get(attack_type, ("Medium", 0.8))
    level = base if confidence >= threshold else downgrade(base)
    if detected_by == "both" and level != "Critical":
        # 두 방법이 독립적으로 같은 결론에 도달하면 신뢰도가 높다
        i = SEVERITY_ORDER.index(level)
        level = SEVERITY_ORDER[max(i - 1, 0)]
    return level, _ACTION.get(attack_type, "담당자 검토 필요.")


def owasp_label(code: str) -> str:
    return f"{code} {_OWASP_NAME.get(code, '')}".strip()


def overall_grade(counts: dict[str, int]) -> tuple[str, str]:
    """서버 단위 종합 판정."""
    if counts.get("Critical"):
        return "위험 (Blocked)", "이 서버는 현재 상태로 도입해서는 안 됩니다."
    if counts.get("High"):
        return "주의 (Conditional)", "지적 사항을 해소한 뒤에만 도입하십시오."
    if counts.get("Medium") or counts.get("Low"):
        return "검토 필요 (Review)", "도입은 가능하나 지적 사항을 확인하십시오."
    return "적합 (Pass)", "탐지된 위험이 없습니다."
