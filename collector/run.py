"""수집기 실행 진입점.

사용법
------
    python -m collector.run                    # 활성화된 서버 전체 수집
    python -m collector.run --server filesystem   # 특정 서버만
    python -m collector.run --config config/servers.yaml

산출물
------
    data/raw/<server>_<YYYYMMDD_HHMM>.json   서버별 스냅샷
    data/raw/_latest.json                    가장 최근 수집 결과 통합본
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from . import console  # noqa: F401  (import 만으로 UTF-8 콘솔 활성화)
from .client import collect_server
from .models import ServerSnapshot

KST = timezone(timedelta(hours=9))
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "raw"


def load_config(config_path: Path) -> list[dict]:
    """servers.yaml 을 읽고 {PROJECT_ROOT} 토큰을 실제 경로로 치환한다."""
    with config_path.open(encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    root = str(PROJECT_ROOT)
    entries = []
    for entry in config.get("servers", []):
        if not entry.get("enabled", True):
            continue
        entry = dict(entry)
        entry["args"] = [
            str(a).replace("{PROJECT_ROOT}", root) for a in entry.get("args", [])
        ]
        entries.append(entry)
    return entries


def save_snapshot(snapshot: ServerSnapshot, stamp: str) -> Path:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    out = RAW_DIR / f"{snapshot.server_name}_{stamp}.json"
    out.write_text(
        snapshot.model_dump_json(indent=2, exclude_none=False),
        encoding="utf-8",
    )
    return out


async def run(config_path: Path, only: str | None) -> int:
    entries = load_config(config_path)
    if only:
        entries = [e for e in entries if e.get("name") == only]
        if not entries:
            print(f"[!] '{only}' 서버를 설정에서 찾지 못했습니다.", file=sys.stderr)
            return 1

    stamp = datetime.now(KST).strftime("%Y%m%d_%H%M")
    print(f"\n대상 서버 {len(entries)}개 수집 시작 (stamp={stamp})\n")

    snapshots: list[ServerSnapshot] = []
    for entry in entries:
        name = entry["name"]
        print(f"→ {name} 접속 중... ", end="", flush=True)
        snapshot = await collect_server(
            name=name,
            command=entry["command"],
            args=entry.get("args", []),
            env=entry.get("env"),
            timeout=float(entry.get("timeout", 90)),
        )
        snapshots.append(snapshot)
        path = save_snapshot(snapshot, stamp)
        if snapshot.status == "ok":
            print(f"도구 {snapshot.tool_count}개 → {path.name}")
        else:
            print(f"실패 → {snapshot.error}")

    # --- 통합본 저장 ---
    combined = {
        "collected_at": datetime.now(KST).isoformat(timespec="seconds"),
        "server_count": len(snapshots),
        "total_tools": sum(s.tool_count for s in snapshots),
        "servers": [json.loads(s.model_dump_json()) for s in snapshots],
    }
    latest = RAW_DIR / "_latest.json"
    latest.write_text(
        json.dumps(combined, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # --- 요약 출력 ---
    ok = [s for s in snapshots if s.status == "ok"]
    print("\n" + "=" * 52)
    print("수집 요약")
    print("=" * 52)
    for s in snapshots:
        print(s.summary_line())
    print("-" * 52)
    print(f"  성공 {len(ok)}/{len(snapshots)} 서버, 총 도구 {combined['total_tools']}개")
    print(f"  통합본: {latest}")
    print("=" * 52 + "\n")

    return 0 if len(ok) == len(snapshots) else 2


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP 도구 정의 수집기")
    parser.add_argument(
        "--config",
        default=str(PROJECT_ROOT / "config" / "servers.yaml"),
        help="서버 설정 파일 경로",
    )
    parser.add_argument("--server", default=None, help="특정 서버만 수집")
    args = parser.parse_args()

    code = asyncio.run(run(Path(args.config), args.server))
    sys.exit(code)


if __name__ == "__main__":
    main()
