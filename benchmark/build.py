"""벤치마크 데이터셋 빌더.

정상 샘플(수집본) + 오염 샘플(합성)을 병합해 라벨링된 데이터셋을 만든다.

산출물
------
    data/benchmark/dataset.json   전체 벤치마크 (정상 52 + 오염 48 = 100건)
    data/benchmark/review.csv     라벨 검수용 (엑셀에서 열어 사람이 확인)

사용법
------
    python -m benchmark.build
    python -m benchmark.build --raw data/raw/_latest.json
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from .mutations import MUTATORS

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RAW = PROJECT_ROOT / "data" / "raw" / "_latest.json"
OUT_DIR = PROJECT_ROOT / "data" / "benchmark"

# 오염 유형별 목표 개수 (합계 48). 정상 52 + 오염 48 = 100.
POISON_PLAN = {
    "hidden_instruction": 16,
    "schema_mismatch": 12,
    "scope_creep": 10,
    "tool_shadowing": 10,
}


def load_normal_tools(raw_path: Path) -> list[dict]:
    """수집본에서 정상 도구를 평탄화. 안정적 정렬로 재현성 보장."""
    data = json.loads(raw_path.read_text(encoding="utf-8"))
    tools = []
    for server in data.get("servers", []):
        if server.get("status") != "ok":
            continue
        sname = server["server_name"]
        for t in server.get("tools", []):
            tools.append({
                "source_server": sname,
                "tool_name": t["tool_name"],
                "description": t.get("description"),
                "input_schema": t.get("input_schema", {}),
                "content_hash": t.get("content_hash", ""),
            })
    tools.sort(key=lambda x: (x["source_server"], x["tool_name"]))
    return tools


def build_normal_samples(tools: list[dict]) -> list[dict]:
    samples = []
    for i, t in enumerate(tools):
        samples.append({
            "sample_id": f"clean_{i:04d}",
            "source_server": t["source_server"],
            "tool_name": t["tool_name"],
            "description": t["description"],
            "input_schema": t["input_schema"],
            "is_malicious": False,
            "attack_type": None,
            "owasp_code": None,
            "difficulty": None,
            "rationale": "공식 레퍼런스 서버에서 수집한 정상 도구 정의",
            "mutation_of": None,
        })
    return samples


def build_poisoned_samples(tools: list[dict]) -> list[dict]:
    """각 오염 유형별로 목표 개수만큼 정상 도구를 변형.

    도구를 전체 서버에 걸쳐 골고루 뽑기 위해, 단순 연속 순회가 아니라
    전체 도구 목록을 큰 보폭(stride)으로 건너뛰며 고른다. 보폭을 도구 수와
    서로소에 가깝게 잡으면 특정 서버에 쏠리지 않고 전 구간이 커버된다.
    """
    samples = []
    counter = 0
    n = len(tools)
    # 각 유형이 전체 도구 목록을 '균등 간격'으로 뽑도록 한다.
    #   index = (offset + round(k * n / target)) % n
    # 이 방식은 보폭이 도구 수와 공약수를 갖는 문제(특정 인덱스만 순환)가
    # 원천적으로 없어, 서버 수가 바뀌어도 항상 전 구간에 고루 분산된다.
    # (이전 고정 보폭 방식은 stride=13, n=52 에서 4개 도구만 반복하는 버그가 있었음)
    plan = [
        ("hidden_instruction", 0),
        ("schema_mismatch", 1),
        ("scope_creep", 2),
        ("tool_shadowing", 3),
    ]
    for attack_type, offset in plan:
        mutator = MUTATORS[attack_type]
        target = POISON_PLAN[attack_type]
        for k in range(target):
            idx = (offset + round(k * n / target)) % n
            base = tools[idx]
            m = mutator(base, k)
            samples.append({
                "sample_id": f"poison_{counter:04d}",
                "source_server": base["source_server"],
                "tool_name": m.tool_name,
                "description": m.description,
                "input_schema": m.input_schema,
                "is_malicious": True,
                "attack_type": m.attack_type,
                "owasp_code": m.owasp_code,
                "difficulty": m.difficulty,
                "rationale": m.rationale,
                "mutation_of": f"{base['source_server']}::{base['tool_name']}",
            })
            counter += 1
    return samples


def write_dataset(samples: list[dict]) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "dataset.json"
    payload = {
        "total": len(samples),
        "clean": sum(1 for s in samples if not s["is_malicious"]),
        "poisoned": sum(1 for s in samples if s["is_malicious"]),
        "samples": samples,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def write_review_csv(samples: list[dict]) -> Path:
    """검수용 CSV. 사람이 눈으로 라벨을 확인하는 용도.

    utf-8-sig(BOM) 로 저장해 Windows 엑셀에서 한글이 깨지지 않게 한다.
    """
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "review.csv"
    cols = ["sample_id", "is_malicious", "attack_type", "owasp_code",
            "difficulty", "source_server", "tool_name", "mutation_of",
            "description_preview", "rationale", "검수의견(직접입력)"]
    with out.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for s in samples:
            desc = (s["description"] or "").replace("\n", " \\n ")
            w.writerow([
                s["sample_id"], s["is_malicious"], s["attack_type"] or "",
                s["owasp_code"] or "", s["difficulty"] or "",
                s["source_server"], s["tool_name"], s["mutation_of"] or "",
                desc[:180], s["rationale"], "",
            ])
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="벤치마크 데이터셋 빌더")
    parser.add_argument("--raw", default=str(DEFAULT_RAW))
    args = parser.parse_args()

    raw_path = Path(args.raw)
    if not raw_path.exists():
        raise SystemExit(f"[!] 수집본이 없습니다: {raw_path}\n    먼저 python -m collector.run 을 실행하세요.")

    tools = load_normal_tools(raw_path)
    clean = build_normal_samples(tools)
    poisoned = build_poisoned_samples(tools)
    samples = clean + poisoned

    ds = write_dataset(samples)
    csv_path = write_review_csv(samples)

    # --- 요약 ---
    print("=" * 54)
    print("벤치마크 데이터셋 생성 완료")
    print("=" * 54)
    print(f"  정상(clean)   : {len(clean)}건")
    print(f"  오염(poisoned): {len(poisoned)}건")
    print("  " + "-" * 40)
    from collections import Counter
    by_type = Counter(s["attack_type"] for s in poisoned)
    by_diff = Counter(s["difficulty"] for s in poisoned)
    for k, v in by_type.items():
        print(f"    {k:<20} {v:>2}건")
    print("  " + "-" * 40)
    print(f"    난이도 분포: {dict(by_diff)}")
    print("  " + "-" * 40)
    print(f"  총 {len(samples)}건")
    print(f"  데이터셋 : {ds}")
    print(f"  검수 CSV : {csv_path}")
    print("=" * 54)
    print("\n다음 단계: data/benchmark/review.csv 를 엑셀로 열어")
    print("           오탐/난이도 라벨을 검수해 주세요.")


if __name__ == "__main__":
    main()
