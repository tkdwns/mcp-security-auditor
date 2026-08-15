"""API 요청·응답 스키마.

Pydantic 모델로 정의해 FastAPI 가 자동으로 검증하고 /docs 문서를 만들게 한다.
입력 제한(도구 수, 문자열 길이)을 스키마 수준에 걸어두면, 핸들러에 도달하기
전에 거부되므로 방어 코드가 한 곳에 모인다.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

# 공개 배포용 입력 상한. Step 3(비용 방어)에서 정책과 함께 재검토한다.
MAX_TOOLS_PER_REQUEST = 20
MAX_DESCRIPTION_CHARS = 8000
MAX_TOOL_NAME_CHARS = 200


class ToolDefinitionIn(BaseModel):
    """감사 대상 MCP 도구 1개."""

    name: str = Field(..., max_length=MAX_TOOL_NAME_CHARS,
                      description="도구 이름", examples=["read_file"])
    description: str | None = Field(
        None, max_length=MAX_DESCRIPTION_CHARS,
        description="도구 설명문. 이 프로젝트의 핵심 감사 대상.")
    inputSchema: dict[str, Any] = Field(
        default_factory=dict, description="JSON Schema 형식의 입력 스키마")


class AuditRequest(BaseModel):
    """감사 요청.

    MCP 서버에 직접 접속하지 않고 **도구 정의를 입력받는다**.
    컨테이너 안에서 임의의 MCP 서버 프로세스를 띄우는 것 자체가 공격면이기
    때문이다(우리가 탐지하려는 대상이 바로 악성 서버다).
    """

    server_name: str = Field("unnamed-server", max_length=100)
    tools: list[ToolDefinitionIn] = Field(..., min_length=1,
                                          max_length=MAX_TOOLS_PER_REQUEST)
    catalog: list[str] | None = Field(
        None, max_length=500,
        description="신뢰된 도구명 목록. 생략하면 서버에 내장된 기본 카탈로그를 쓴다.")


class Finding(BaseModel):
    tool_name: str
    severity: Literal["Critical", "High", "Medium", "Low", "Info"]
    owasp: str
    attack_type: str
    confidence: float
    detected_by: Literal["llm", "rule", "both"]
    evidence: str = ""
    evidence_verified: bool | None = None
    reasoning: str = ""
    action: str = ""


class RuleNote(BaseModel):
    """규칙만 반응한 항목. 위험 목록과 종합 판정에서는 제외된다."""

    tool_name: str
    rule_signals: list[str] = Field(default_factory=list)
    details: list[str] = Field(default_factory=list)


class AuditResult(BaseModel):
    server_name: str
    model: str
    n_tools: int
    grade: str
    verdict: str
    severity_counts: dict[str, int] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    notes: list[RuleNote] = Field(default_factory=list)
    safe_tools: list[str] = Field(default_factory=list)
    elapsed_sec: float = 0.0
    cost_krw: float = 0.0


class JobCreated(BaseModel):
    job_id: str
    status: Literal["queued"]
    poll_url: str


class JobStatus(BaseModel):
    job_id: str
    status: Literal["queued", "running", "done", "error"]
    progress: str = ""
    created_at: str = ""
    result: AuditResult | None = None
    error: str | None = None
    notice: str | None = Field(
        None, description="예산 소진 등으로 데모 결과가 반환된 경우의 안내 문구")


class HealthResponse(BaseModel):
    status: Literal["ok"]
    version: str
    llm_available: bool = Field(
        ..., description="ANTHROPIC_API_KEY 가 설정되어 실제 판별이 가능한지")
    catalog_size: int
    demos: list[str]
    budget: dict[str, Any] = Field(default_factory=dict, description="오늘의 판별 예산 현황")
    limits: dict[str, Any] = Field(default_factory=dict, description="적용 중인 제한값")
