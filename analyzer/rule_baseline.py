"""규칙 엔진을 벤치마크 전체에 돌려 baseline 성능을 측정한다.

이 스크립트의 결과가 3주차 리포트의 '규칙만 사용 시' 성능이 된다.
LLM 은 아직 호출하지 않으므로 비용은 0원이다.

사용법:
    python -m analyzer.rule_baseline
"""

from __future__ import annotations

import json
from pathlib import Path

from .rules import evaluate_sample

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET = PROJECT_ROOT / "data" / "benchmark" / "dataset.json"
OUT_DIR = PROJECT_ROOT / "data" / "results"


def confusion(samples, preds):
    tp = fp = tn = fn = 0
    for s, p in zip(samples, preds):
        actual = s["is_malicious"]
        if p and actual:
            tp += 1
        elif p and not actual:
            fp += 1
        elif not p and not actual:
            tn += 1
        else:
            fn += 1
    return tp, fp, tn, fn


def prf(tp, fp, tn, fn):
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return prec, rec, f1, fpr


def main() -> None:
    if not DATASET.exists():
        raise SystemExit(f"[!] 데이터셋이 없습니다: {DATASET}\n    먼저 python -m benchmark.build 실행")

    data = json.loads(DATASET.read_text(encoding="utf-8"))
    samples = data["samples"]

    # '알려진 정상 도구명' 카탈로그 = clean 샘플의 도구명 집합
    # (실무에선 신뢰된 서버의 도구 목록. 여기선 clean 라벨을 카탈로그로 사용)
    known_names = {s["tool_name"] for s in samples if not s["is_malicious"]}

    results = [evaluate_sample(s, known_names) for s in samples]
    preds = [r.rule_flag for r in results]

    tp, fp, tn, fn = confusion(samples, preds)
    prec, rec, f1, fpr = prf(tp, fp, tn, fn)

    # 저장
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "rule_baseline.json"
    payload = {
        "method": "rule_only",
        "metrics": {"precision": round(prec, 4), "recall": round(rec, 4),
                    "f1": round(f1, 4), "fpr": round(fpr, 4),
                    "tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "per_sample": [r.to_row() for r in results],
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    # 유형별 재현율
    from collections import defaultdict
    by_type_total = defaultdict(int)
    by_type_hit = defaultdict(int)
    by_diff_total = defaultdict(int)
    by_diff_hit = defaultdict(int)
    for s, p in zip(samples, preds):
        if s["is_malicious"]:
            by_type_total[s["attack_type"]] += 1
            by_diff_total[s["difficulty"]] += 1
            if p:
                by_type_hit[s["attack_type"]] += 1
                by_diff_hit[s["difficulty"]] += 1

    print("=" * 56)
    print("규칙 엔진 baseline 성능 (LLM 미사용, 비용 0원)")
    print("=" * 56)
    print(f"  Precision {prec:.3f}  Recall {rec:.3f}  F1 {f1:.3f}  FPR {fpr:.3f}")
    print(f"  TP {tp}  FP {fp}  TN {tn}  FN {fn}")
    print("-" * 56)
    print("  [유형별 재현율]")
    for t in by_type_total:
        print(f"    {t:<20} {by_type_hit[t]}/{by_type_total[t]}")
    print("  [난이도별 재현율]")
    for d in ["easy", "medium", "hard"]:
        if by_diff_total[d]:
            print(f"    {d:<20} {by_diff_hit[d]}/{by_diff_total[d]}")
    print("-" * 56)
    # 오탐(정상을 악성으로) 목록 — 하드 네거티브 확인
    print("  [오탐 목록 (정상인데 규칙에 걸림)]")
    fps = [(s["sample_id"], s["tool_name"]) for s, p in zip(samples, preds)
           if p and not s["is_malicious"]]
    if fps:
        for sid, tn_ in fps:
            print(f"    {sid}  {tn_}")
    else:
        print("    (없음)")
    print("=" * 56)
    print(f"  저장: {out}")
    print("\n해석: 규칙만으로 이 정도가 한계다. 특히 'hard' 케이스와")
    print("      의미 판별이 필요한 항목에서 LLM 이 얼마나 끌어올리는지가 2~3주차 핵심.")


if __name__ == "__main__":
    main()
