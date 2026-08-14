"""LLM 기반 판별기.

핵심 설계
---------
1) 구조화 출력: report_verdict 툴을 강제(tool_choice)해 JSON 스키마로 받는다.
   자유 텍스트 파싱을 없애 평가 자동화를 보장한다.
2) 근거 인용: evidence_span 에 원문을 그대로 인용하게 해 환각을 억제한다.
   (인용문이 실제 설명문에 있는지 나중에 검증 가능)
3) 프롬프트 캐싱: OWASP 컨텍스트 블록에 cache_control 을 걸어 반복 입력을
   정가의 10%로 낮춘다.
4) 안전장치: 총 호출 수 상한(call cap)으로 사고성 과금을 막는다.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from .owasp_context import OWASP_MCP_CONTEXT, VERDICT_TOOL

# 모델별 100만 토큰당 단가 (USD). 2026-08 검증치.
# ⚠️ Sonnet 5 는 2026-08-31 까지 한시 요금($2/$10), 이후 $3/$15.
PRICING = {
    "claude-sonnet-5": {"in": 2.0, "out": 10.0},
    "claude-haiku-4-5-20251001": {"in": 1.0, "out": 5.0},
    "claude-opus-5": {"in": 5.0, "out": 25.0},
}
USD_TO_KRW = 1380  # 환산용 근사치 (리포트엔 실제 환율 재확인 권장)


@dataclass
class Verdict:
    sample_id: str
    is_malicious: bool = False
    confidence: float = 0.0
    owasp_code: str = "NONE"
    attack_type: str = "none"
    evidence_span: str = ""
    reasoning: str = ""
    evidence_verified: bool | None = None  # 인용문이 원문에 실재하는지
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    error: str | None = None


def build_user_prompt(sample: dict[str, Any]) -> str:
    schema_str = json.dumps(sample.get("input_schema", {}), ensure_ascii=False, indent=2)
    return (
        f"다음 MCP 도구 정의를 감사하세요.\n\n"
        f"[도구 이름]\n{sample['tool_name']}\n\n"
        f"[설명문 description]\n{sample.get('description') or '(없음)'}\n\n"
        f"[입력 스키마 input_schema]\n{schema_str}\n\n"
        f"report_verdict 툴로 판정 결과를 보고하세요."
    )


def _norm_for_match(t: str | None) -> str:
    """근거 대조용 정규화: 공백 전부 제거 + 소문자 + 따옴표 제거.

    모델이 JSON 을 다른 들여쓰기/따옴표로 재포맷해 인용해도 매칭되도록 한다.
    """
    import re as _re
    return _re.sub(r"\s+", "", (t or "")).lower().replace('"', "").replace("'", "")


def verify_evidence(
    span: str, description: str | None, input_schema: dict | None = None
) -> bool | None:
    """모델이 인용한 근거가 원문에 실제 존재하는지 검증(환각 탐지).

    중요: schema_mismatch 공격의 근거는 '스키마' 안에 있다. 따라서 설명문뿐
    아니라 input_schema 직렬화 텍스트까지 함께 대조해야 한다. (설명문만 보던
    초기 버전은 스키마 근거를 전부 '환각'으로 오판했다.)
    """
    if not span:
        return None
    import json as _json
    hay = _norm_for_match(description) + _norm_for_match(
        _json.dumps(input_schema or {}, ensure_ascii=False)
    )
    return _norm_for_match(span)[:30] in hay


class LLMJudge:
    def __init__(self, model: str, call_cap: int = 120):
        self.model = model
        self.call_cap = call_cap
        self._calls = 0
        self._client = None

    def _client_lazy(self):
        if self._client is None:
            from anthropic import Anthropic
            key = os.environ.get("ANTHROPIC_API_KEY")
            if not key:
                raise SystemExit("[!] ANTHROPIC_API_KEY 가 없습니다. .env 를 확인하세요.")
            self._client = Anthropic(api_key=key)
        return self._client

    def judge(self, sample: dict[str, Any], dry_run: bool = False) -> Verdict:
        v = Verdict(sample_id=sample["sample_id"])
        user_prompt = build_user_prompt(sample)

        if dry_run:
            v.reasoning = "[dry-run] 호출 안 함"
            print(f"\n----- {sample['sample_id']} ({sample['tool_name']}) -----")
            print(user_prompt[:600])
            return v

        if self._calls >= self.call_cap:
            v.error = f"호출 상한({self.call_cap}) 도달로 건너뜀"
            return v

        try:
            client = self._client_lazy()
            self._calls += 1
            resp = client.messages.create(
                model=self.model,
                max_tokens=600,
                system=[{
                    "type": "text",
                    "text": OWASP_MCP_CONTEXT,
                    "cache_control": {"type": "ephemeral"},  # 프롬프트 캐싱
                }],
                tools=[VERDICT_TOOL],
                tool_choice={"type": "tool", "name": "report_verdict"},
                messages=[{"role": "user", "content": user_prompt}],
            )
            # 토큰/비용
            u = resp.usage
            v.input_tokens = u.input_tokens
            v.output_tokens = u.output_tokens
            v.cache_read_tokens = getattr(u, "cache_read_input_tokens", 0) or 0

            # 구조화 출력 파싱
            block = next((b for b in resp.content if b.type == "tool_use"), None)
            if block is None:
                v.error = "tool_use 블록 없음"
                return v
            data = block.input
            v.is_malicious = bool(data.get("is_malicious", False))
            v.confidence = float(data.get("confidence", 0.0))
            v.owasp_code = data.get("owasp_code", "NONE")
            v.attack_type = data.get("attack_type", "none")
            v.evidence_span = data.get("evidence_span", "") or ""
            v.reasoning = data.get("reasoning", "")
            v.evidence_verified = verify_evidence(
                v.evidence_span, sample.get("description"), sample.get("input_schema")
            )
        except Exception as exc:  # 네트워크/429 등
            v.error = f"{type(exc).__name__}: {exc}"
        return v

    def cost_krw(self, verdicts: list[Verdict]) -> dict[str, float]:
        price = PRICING.get(self.model, {"in": 2.0, "out": 10.0})
        in_tok = sum(v.input_tokens for v in verdicts)
        cache_tok = sum(v.cache_read_tokens for v in verdicts)
        out_tok = sum(v.output_tokens for v in verdicts)
        # 캐시 히트분은 정가의 10%
        fresh_in = max(0, in_tok - cache_tok)
        usd = (fresh_in * price["in"] + cache_tok * price["in"] * 0.1
               + out_tok * price["out"]) / 1_000_000
        return {
            "input_tokens": in_tok, "cache_read_tokens": cache_tok,
            "output_tokens": out_tok,
            "usd": round(usd, 4), "krw": round(usd * USD_TO_KRW, 1),
        }
