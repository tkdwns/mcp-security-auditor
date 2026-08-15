"""홀드아웃 검증셋 빌더.

프롬프트 과적합 여부를 검증하기 위한 별도 테스트셋을 만든다.
공격 표현·파라미터명·리네이밍 패턴이 기존 벤치마크 및 few-shot 예시와
전혀 겹치지 않는다.

산출물:
    data/benchmark/holdout.json
    data/benchmark/holdout_review.csv
사용법:
    python -m benchmark.build_holdout
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .build import DEFAULT_RAW, OUT_DIR, load_normal_tools, write_review_csv
from .holdout_mutations import HOLDOUT_MUTATORS
from .holdout2_mutations import HOLDOUT2_MUTATORS

VERSIONS = {"v1": HOLDOUT_MUTATORS, "v2": HOLDOUT2_MUTATORS}

# 홀드아웃 오염 구성 (합계 36). 정상은 수집본 전체(52)를 그대로 사용.
HOLDOUT_PLAN = {
    "hidden_instruction": 10,
    "schema_mismatch": 9,
    "scope_creep": 9,
    "tool_shadowing": 8,
}


# 버전별 base 도구 선택 오프셋.
# v2 는 v1 과 다른 도구에서 출발해, 두 홀드아웃셋이 서로 독립 표본이 되게 한다.
# (같은 오프셋을 쓰면 설명문을 바꾸지 않는 schema_mismatch 계열에서
#  v1 과 v2 의 샘플이 동일한 도구를 재사용하게 된다)
OFFSETS = {
    "v1": {"hidden_instruction": 4, "schema_mismatch": 7,
           "scope_creep": 9, "tool_shadowing": 6},
    "v2": {"hidden_instruction": 21, "schema_mismatch": 30,
           "scope_creep": 38, "tool_shadowing": 45},
}


def build(tools: list[dict], mutators: dict, offsets: dict) -> list[dict]:
    samples = []
    for i, t in enumerate(tools):
        samples.append({
            "sample_id": f"hclean_{i:04d}",
            "source_server": t["source_server"], "tool_name": t["tool_name"],
            "description": t["description"], "input_schema": t["input_schema"],
            "is_malicious": False, "attack_type": None, "owasp_code": None,
            "difficulty": None, "mutation_of": None,
            "rationale": "공식 레퍼런스 서버에서 수집한 정상 도구 정의",
        })

    n = len(tools)
    counter = 0
    # 기존 벤치마크와 '다른' 도구가 뽑히도록 오프셋을 다르게 준다.
    for attack_type, offset in offsets.items():
        mut = mutators[attack_type]
        target = HOLDOUT_PLAN[attack_type]
        for k in range(target):
            base = tools[(offset + round(k * n / target)) % n]
            m = mut(base, k)
            samples.append({
                "sample_id": f"hpoison_{counter:04d}",
                "source_server": base["source_server"], "tool_name": m.tool_name,
                "description": m.description, "input_schema": m.input_schema,
                "is_malicious": True, "attack_type": m.attack_type,
                "owasp_code": m.owasp_code, "difficulty": m.difficulty,
                "rationale": m.rationale,
                "mutation_of": f"{base['source_server']}::{base['tool_name']}",
            })
            counter += 1
    return samples


def main() -> None:
    ap = argparse.ArgumentParser(description="홀드아웃 검증셋 빌더")
    ap.add_argument("--raw", default=str(DEFAULT_RAW))
    ap.add_argument("--version", default="v1", choices=["v1", "v2"],
                    help="v1=신규표현 / v2=난이도 대응(더 어려움)")
    args = ap.parse_args()

    raw = Path(args.raw)
    if not raw.exists():
        raise SystemExit(f"[!] 수집본 없음: {raw}")

    tools = load_normal_tools(raw)
    samples = build(tools, VERSIONS[args.version], OFFSETS[args.version])

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fname = "holdout.json" if args.version == "v1" else f"holdout_{args.version}.json"
    out = OUT_DIR / fname
    out.write_text(json.dumps({
        "total": len(samples),
        "clean": sum(1 for s in samples if not s["is_malicious"]),
        "poisoned": sum(1 for s in samples if s["is_malicious"]),
        "version": args.version,
        "note": ("프롬프트 과적합 검증용 홀드아웃셋. 공격 표현이 학습셋/few-shot 예시와 겹치지 않음."
                 + (" v2 는 난이도를 학습셋 hard 수준에 맞춰 재설계됨." if args.version == "v2" else "")),
        "samples": samples,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    # 검수 CSV (기존 함수 재사용 후 파일명만 변경)
    csv_path = write_review_csv(samples)
    final_csv = OUT_DIR / (f"holdout_review.csv" if args.version == "v1"
                           else f"holdout_{args.version}_review.csv")
    csv_path.replace(final_csv)

    from collections import Counter
    by_t = Counter(s["attack_type"] for s in samples if s["is_malicious"])
    by_d = Counter(s["difficulty"] for s in samples if s["is_malicious"])
    print("=" * 56)
    print(f"홀드아웃 검증셋 생성 완료 ({args.version})")
    print("=" * 56)
    print(f"  정상 {sum(1 for s in samples if not s['is_malicious'])}건 / "
          f"오염 {sum(1 for s in samples if s['is_malicious'])}건")
    for k, v in by_t.items():
        print(f"    {k:<20} {v}건")
    print(f"  난이도: {dict(by_d)}")
    print(f"  데이터셋: {out}")
    print(f"  검수 CSV: {final_csv}")
    print("=" * 56)
    print("\n용도: 전략 A(zero-shot) vs B(few-shot) 를 이 셋에 돌려")
    print("      few-shot 의 개선이 진짜 일반화인지 과적합인지 판정한다.")


if __name__ == "__main__":
    main()
