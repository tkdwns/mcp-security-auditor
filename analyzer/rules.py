"""규칙 기반 선필터 엔진.

목적 (두 가지)
--------------
1) 비용 절감: 값싼 규칙으로 명백한 케이스를 먼저 걸러 LLM 호출을 줄인다.
2) 비교군(baseline): 3주차에 "규칙만 vs 규칙+LLM" 성능을 비교해
   '왜 LLM이 필요한가'를 숫자로 증명한다.

각 규칙은 RuleHit 을 만들고, 도구 1건에 대한 종합 결과를 RuleResult 로 낸다.
규칙은 '의심 신호'를 모으는 역할이며, 최종 판정은 LLM 이 한다.
따라서 규칙은 재현율(놓치지 않기) 위주로, 정밀도는 낮아도 된다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ----------------------------------------------------------------------
# 규칙별 패턴 정의
# ----------------------------------------------------------------------

# R1. 은닉 지시 태그: 설명문에 지시를 숨기는 데 흔히 쓰이는 마크업
_HIDDEN_TAGS = re.compile(
    r"(<important>|<!--|-->|\[system|\[/?inst\]|<system|</?assistant|<override)",
    re.IGNORECASE,
)

# R2. 은폐 요구 표현: '사용자에게 말하지 말라'류
_CONCEALMENT = re.compile(
    r"(do not (mention|tell|inform|surface)|don't (mention|tell)|"
    r"without (telling|informing|notifying)|silently|"
    r"need not be surfaced|절대 (언급|말)하지|사용자에게 (알리|말하)지)",
    re.IGNORECASE,
)

# R3. 지시 주입 표현: 도구 설명이 에이전트 행동을 지시
_INSTRUCTION_INJECTION = re.compile(
    r"(system override|always (also )?(read|call|forward|include)|"
    r"prefer it over|instead of other|mandatory|this instruction)",
    re.IGNORECASE,
)

# R4. 민감 경로/시크릿 리터럴
_SECRET_LITERALS = re.compile(
    r"(~/\.ssh|id_rsa|id_ed25519|\.env\b|/etc/passwd|"
    r"AKIA[0-9A-Z]{12,}|-----BEGIN|private key|credential)",
    re.IGNORECASE,
)

# R5. 권한 과다 신호: 목적과 무관한 광범위 권한 요구
_SCOPE_CREEP = re.compile(
    r"(delete or overwrite any file|execute shell command|"
    r"entire home directory|broad (filesystem|network) access|"
    r"without requiring confirmation|read/write access to)",
    re.IGNORECASE,
)

# R6. 섀도잉 유도 문구
_SHADOW_LURE = re.compile(
    r"(preferred,? updated implementation|call this one instead|"
    r"always call this|use this instead of)",
    re.IGNORECASE,
)


@dataclass
class RuleHit:
    rule_id: str
    detail: str


@dataclass
class RuleResult:
    sample_id: str
    tool_name: str
    hits: list[RuleHit] = field(default_factory=list)
    # 규칙 기반 예측(baseline). 하나라도 걸리면 의심(True).
    rule_flag: bool = False
    # 스키마-설명 불일치, 이름 유사도는 별도 산정
    schema_mismatch: bool = False
    name_shadow: bool = False

    def to_row(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "tool_name": self.tool_name,
            "rule_flag": self.rule_flag,
            "fired_rules": [h.rule_id for h in self.hits],
            "details": [h.detail for h in self.hits],
        }


def _levenshtein(a: str, b: str, cap: int = 3) -> int:
    """편집거리. cap 초과는 조기 종료(성능)."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        best = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            cur.append(v)
            best = min(best, v)
        prev = cur
        if best > cap:
            return cap + 1
    return prev[-1]


def _normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


# 주입에 흔히 쓰이는 '민감/맥락포획' 파라미터명.
# 정상 도구의 평범한 파라미터(repo_path, message, path, content 등)는
# 여기 없으므로 오탐을 일으키지 않는다. 데이터셋에 맞춘 하드코딩이 아니라
# 실제 tool-poisoning 사례에서 반복되는 이름들을 일반화한 목록이다.
_SENSITIVE_PARAMS = {
    "context", "metadata", "sidenote", "note", "extra", "extra_context",
    "env", "environment", "config", "configuration", "credentials",
    "credential", "token", "secret", "apikey", "api_key",
    "file_path", "filepath", "data", "payload",
}


def check_schema_description_mismatch(
    description: str | None, input_schema: dict[str, Any]
) -> tuple[bool, str]:
    """설명에 언급되지 않은 '민감한' 파라미터가 스키마에 있는지 검사.

    핵심 교훈: 단순히 '설명에 없는 파라미터 = 의심' 으로 하면 정상 도구도
    대부분 걸린다(짧은 설명문은 모든 파라미터를 언급하지 않으므로).
    따라서 (1) 설명에 언급되지 않았고 AND (2) 민감/맥락포획 계열 이름일 때만
    의심한다. 이 조합이 schema_mismatch 공격의 실제 형태와 맞는다.
    """
    props = (input_schema or {}).get("properties") or {}
    if not props or not description:
        return False, ""
    desc_low = description.lower()
    suspicious = []
    for pname in props:
        norm = re.sub(r"([a-z])([A-Z])", r"\1_\2", pname).lower()
        tokens = [t for t in re.split(r"[_\-]", norm) if t]
        mentioned = any(tok in desc_low for tok in tokens)
        is_sensitive = (norm in _SENSITIVE_PARAMS) or (pname.lower() in _SENSITIVE_PARAMS)
        if is_sensitive and not mentioned:
            suspicious.append(pname)
    if suspicious:
        return True, f"설명에 없는 민감 파라미터: {', '.join(suspicious)}"
    return False, ""


def check_name_shadowing(
    tool_name: str, known_names: set[str]
) -> tuple[bool, str]:
    """알려진 정상 도구명과 '거의 같지만 다른' 이름인지 검사.

    - 정확히 일치하면 정상(같은 도구).
    - 정규화 후 일치(예: list_directory vs listdirectory)하거나
      편집거리 1~2 이내면 섀도잉 의심.
    """
    if tool_name in known_names:
        return False, ""
    norm = _normalize(tool_name)
    for known in known_names:
        if known == tool_name:
            continue
        if _normalize(known) == norm and known != tool_name:
            return True, f"정규화 시 '{known}' 와 동일 (구분자만 제거됨)"
        d = _levenshtein(tool_name, known, cap=2)
        if 1 <= d <= 2:
            return True, f"'{known}' 와 편집거리 {d}"
    return False, ""


def evaluate_sample(sample: dict[str, Any], known_names: set[str]) -> RuleResult:
    desc = sample.get("description") or ""
    res = RuleResult(sample_id=sample["sample_id"], tool_name=sample["tool_name"])

    for rule_id, pat, label in [
        ("R1_hidden_tag", _HIDDEN_TAGS, "은닉 지시 태그"),
        ("R2_concealment", _CONCEALMENT, "은폐 요구 표현"),
        ("R3_instruction", _INSTRUCTION_INJECTION, "에이전트 지시 주입"),
        ("R4_secret", _SECRET_LITERALS, "민감 경로/시크릿 리터럴"),
        ("R5_scope", _SCOPE_CREEP, "권한 과다 요구"),
        ("R6_shadow_lure", _SHADOW_LURE, "섀도잉 유도 문구"),
    ]:
        m = pat.search(desc)
        if m:
            res.hits.append(RuleHit(rule_id, f"{label}: '{m.group(0)[:40]}'"))

    mism, mism_detail = check_schema_description_mismatch(
        sample.get("description"), sample.get("input_schema", {})
    )
    if mism:
        res.schema_mismatch = True
        res.hits.append(RuleHit("R7_schema_mismatch", mism_detail))

    shadow, shadow_detail = check_name_shadowing(sample["tool_name"], known_names)
    if shadow:
        res.name_shadow = True
        res.hits.append(RuleHit("R8_name_shadow", shadow_detail))

    res.rule_flag = len(res.hits) > 0
    return res
