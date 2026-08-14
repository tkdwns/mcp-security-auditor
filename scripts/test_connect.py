"""[Step 2] MCP 서버 1개 연결 테스트.

수집기를 만들기 전에, 가장 먼저 확인해야 할 것은 딱 하나다.
    "내 파이썬이 MCP 서버와 말이 통하는가?"

이 스크립트는 Filesystem 서버 하나에만 붙어 도구 이름을 출력한다.
성공하면 read_file, write_file, list_directory 같은 이름이 주르륵 나온다.

실행:
    python scripts/test_connect.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# 프로젝트 루트를 import 경로에 추가 (scripts/ 에서 실행해도 동작하도록)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collector import console  # noqa: E402,F401  (UTF-8 콘솔)
from collector.client import collect_server  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SANDBOX = PROJECT_ROOT / "sandbox"


async def main() -> None:
    print("=" * 56)
    print("MCP Filesystem 서버 연결 테스트")
    print("=" * 56)
    print(f"샌드박스 경로: {SANDBOX}")
    print("최초 실행 시 npx 가 패키지를 내려받느라 30초 정도 걸릴 수 있습니다.\n")

    snapshot = await collect_server(
        name="filesystem",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", str(SANDBOX)],
        timeout=120,
    )

    if snapshot.status != "ok":
        print(f"[실패] {snapshot.error}\n")
        print("점검 사항:")
        print("  1. node --version / npx --version 이 정상 출력되는가")
        print("  2. sandbox 폴더가 존재하는가")
        print("  3. 사내망/방화벽이 npm 레지스트리를 막고 있지는 않은가")
        sys.exit(1)

    print(f"[성공] 도구 {snapshot.tool_count}개를 찾았습니다.\n")
    for i, tool in enumerate(snapshot.tools, 1):
        desc = (tool.description or "").replace("\n", " ").strip()
        preview = desc[:70] + ("..." if len(desc) > 70 else "")
        print(f"  {i:2d}. {tool.tool_name}")
        print(f"      설명: {preview}")
        print(f"      파라미터: {', '.join(tool.param_names) or '(없음)'}")
        print(f"      해시: {tool.content_hash[:16]}...")
        print()

    print("=" * 56)
    print("이 '설명' 문장들이 바로 우리가 앞으로 감사할 대상입니다.")
    print("=" * 56)


if __name__ == "__main__":
    asyncio.run(main())
