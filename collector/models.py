"""수집한 MCP 도구 정의를 표현하는 데이터 모델.

설계 의도
---------
- `description` 과 `input_schema` 가 이 프로젝트의 실제 감사 대상이다.
  (도구 설명문은 모델 컨텍스트에 '신뢰된 지시문'으로 주입되므로 공격 표면이 된다.)
- `content_hash` / `collected_at` 은 4주차 확장 기능인 '럭풀(Rug Pull) 탐지'를 위한 것이다.
  같은 도구를 나중에 다시 수집했을 때 해시가 달라지면 정의가 몰래 바뀐 것이다.
- `raw` 를 통째로 보관해 두면 나중에 필드를 추가해도 재수집이 필요 없다.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, Field


def compute_content_hash(
    name: str,
    description: str | None,
    input_schema: dict[str, Any] | None,
) -> str:
    """도구 정의의 내용 해시. 키 정렬로 순서에 흔들리지 않게 한다."""
    payload = json.dumps(
        {
            "name": name,
            "description": description or "",
            "input_schema": input_schema or {},
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ToolDefinition(BaseModel):
    """MCP 서버가 노출하는 도구 1개."""

    tool_name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)
    content_hash: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)

    # --- 편의 속성 (2주차 판별기에서 사용) ---
    @property
    def description_length(self) -> int:
        return len(self.description or "")

    @property
    def param_names(self) -> list[str]:
        props = self.input_schema.get("properties") or {}
        return list(props.keys())

    @classmethod
    def from_mcp_tool(cls, tool: Any) -> "ToolDefinition":
        """MCP SDK 의 Tool 객체를 우리 모델로 변환."""
        if hasattr(tool, "model_dump"):
            raw = tool.model_dump(mode="json", exclude_none=False)
        else:  # 방어적 처리
            raw = dict(tool)

        name = raw.get("name") or ""
        description = raw.get("description")
        # MCP 스펙은 camelCase(inputSchema)를 쓴다. snake_case 도 대비.
        schema = raw.get("inputSchema") or raw.get("input_schema") or {}

        return cls(
            tool_name=name,
            description=description,
            input_schema=schema,
            content_hash=compute_content_hash(name, description, schema),
            raw=raw,
        )


class ServerSnapshot(BaseModel):
    """특정 시점에 수집한 MCP 서버 1개의 전체 도구 정의."""

    server_name: str
    transport: str = "stdio"
    command: str = ""
    args: list[str] = Field(default_factory=list)
    collected_at: str = ""
    status: str = "ok"  # ok | error
    error: str | None = None
    tool_count: int = 0
    tools: list[ToolDefinition] = Field(default_factory=list)

    def summary_line(self) -> str:
        if self.status == "ok":
            return f"  [OK]   {self.server_name:<12} 도구 {self.tool_count}개"
        return f"  [FAIL] {self.server_name:<12} {self.error}"
