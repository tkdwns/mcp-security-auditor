"""MCP 서버에 stdio 로 접속해 도구 정의를 수집하는 클라이언트 래퍼.

동작 원리
---------
    [이 스크립트] --stdio(표준입출력)--> [자식 프로세스로 띄운 MCP 서버]
        1) initialize()  : 프로토콜 핸드셰이크
        2) list_tools()  : "너 무슨 도구 가지고 있어?"
        3) 반환된 도구 정의를 ToolDefinition 으로 변환

MCP 서버는 네트워크 서버가 아니라 '자식 프로세스'다. 우리 프로그램이 서버를
직접 실행하고 표준입출력으로 대화한다. 이것이 로컬 MCP 의 기본 전송 방식이다.
"""

from __future__ import annotations

import os
import shutil
import sys
from datetime import datetime, timedelta, timezone

import anyio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .models import ServerSnapshot, ToolDefinition

KST = timezone(timedelta(hours=9))

# Windows 에서 실행 파일을 찾을 때 붙여볼 확장자
_WIN_EXTS = (".cmd", ".exe", ".bat", ".ps1")


def resolve_command(command: str) -> str:
    """실행 커맨드의 절대경로를 찾는다.

    Windows 에서 `npx`, `uvx` 는 실제로 `npx.cmd`, `uvx.exe` 형태라서
    문자열 그대로 subprocess 에 넘기면 FileNotFoundError 가 난다.
    MCP 를 Windows 에서 처음 붙일 때 가장 흔하게 막히는 지점이다.
    """
    found = shutil.which(command)
    if found:
        return found

    if sys.platform == "win32":
        for ext in _WIN_EXTS:
            found = shutil.which(command + ext)
            if found:
                return found

    raise FileNotFoundError(
        f"'{command}' 를 PATH 에서 찾을 수 없습니다. "
        f"설치 여부와 PATH 등록을 확인하세요."
    )


async def collect_server(
    name: str,
    command: str,
    args: list[str],
    env: dict[str, str] | None = None,
    timeout: float = 90.0,
) -> ServerSnapshot:
    """MCP 서버 1개에 접속해 도구 정의를 수집한다.

    실패해도 예외를 밖으로 던지지 않는다. 서버 하나가 죽어도 나머지 수집은
    계속되어야 하고, 실패 사실 자체도 감사 리포트의 재료이기 때문이다.
    """
    snapshot = ServerSnapshot(
        server_name=name,
        command=command,
        args=list(args),
        collected_at=datetime.now(KST).isoformat(timespec="seconds"),
    )

    # --- 1) 실행 커맨드 해석 ---
    try:
        resolved = resolve_command(command)
    except FileNotFoundError as exc:
        snapshot.status = "error"
        snapshot.error = str(exc)
        return snapshot

    # --- 2) 환경변수 구성 ---
    # 부모 환경을 그대로 물려준다. Windows 의 npx 는 PATH/APPDATA/SystemRoot 가
    # 없으면 동작하지 않는다.
    merged_env = dict(os.environ)
    if env:
        merged_env.update(env)

    params = StdioServerParameters(command=resolved, args=list(args), env=merged_env)

    # --- 3) 접속 및 수집 ---
    try:
        with anyio.fail_after(timeout):
            async with stdio_client(params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    result = await session.list_tools()
                    snapshot.tools = [
                        ToolDefinition.from_mcp_tool(t) for t in result.tools
                    ]
                    snapshot.tool_count = len(snapshot.tools)
    except TimeoutError:
        snapshot.status = "error"
        snapshot.error = (
            f"{timeout:.0f}초 안에 응답이 없었습니다. "
            f"패키지를 처음 내려받는 중이라면 잠시 후 다시 실행해 보세요."
        )
    except Exception as exc:
        snapshot.status = "error"
        snapshot.error = _describe_exception(exc)

    return snapshot


def _describe_exception(exc: BaseException) -> str:
    """anyio 태스크그룹은 실제 원인을 ExceptionGroup 안에 감싸서 던진다.

    그대로 로그에 남기면 'unhandled errors in a TaskGroup' 같은 쓸모없는
    메시지만 남으므로, 가장 안쪽의 실제 예외를 꺼내서 보여준다.
    """
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return f"{type(exc).__name__}: {exc}"
