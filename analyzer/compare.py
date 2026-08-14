"""세 가지 방법(규칙 / LLM / 하이브리드)의 성능을 비교한다.

이미 저장된 결과 파일만 읽으므로 API 호출이 없다(무료). 저장된 LLM 판정의
근거 검증도 수정된 기준(설명문+스키마)으로 다시 계산해 정정한다.

산출물:
    data/results/comparison.json
사용법:
    python -m analyzer.compare
"""

from __future__ import annotations

import json
from pathlib import Path

from . import console  # noqa: F401
from .rules import evaluate_sample
from .llm_judge import verify_evidence

ROOT = Path(__file__).resolve().parent.parent
DS = ROOT / "data" / "benchmark" / "dataset.json"
RES = ROOT / "data" / "results"


def metrics(ds, pred):
    tp = fp = tn = fn = 0
    for sid, s in ds.items():
        p = pred[sid]; a = s["is_malicious"]
        if p and a: tp += 1
        elif p and not a: fp += 1
        elif not p and not a: tn += 1
        else: fn += 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return dict(precision=round(prec, 4), recall=round(rec, 4),
                f1=round(f1, 4), fpr=round(fpr, 4),
                tp=tp, fp=fp, tn=tn, fn=fn)


def per_category_recall(ds, pred):
    from collections import defaultdict
    tot = defaultdict(int); hit = defaultdict(int)
    for sid, s in ds.items():
        if s["is_malicious"]:
            key = f"{s['attack_type']}/{s['difficulty']}"
            tot[s["attack_type"]] += 1; tot[key] += 1
            if pred[sid]:
                hit[s["attack_type"]] += 1; hit[key] += 1
    return {k: f"{hit[k]}/{tot[k]}" for k in sorted(tot)}


def main() -> None:
    ds = {s["sample_id"]: s for s in json.loads(DS.read_text(encoding="utf-8"))["samples"]}
    known = {s["tool_name"] for s in ds.values() if not s["is_malicious"]}

    # 규칙 예측
    rule_pred = {sid: evaluate_sample(s, known).rule_flag for sid, s in ds.items()}

    # LLM 예측 (저장된 결과에서). 여러 모델 파일 지원.
    llm_files = sorted(RES.glob("llm_*.json"))
    if not llm_files:
        raise SystemExit("[!] LLM 결과가 없습니다. 먼저 python -m analyzer.run 실행")

    report = {"methods": {}, "per_category": {}}
    report["methods"]["rule_only"] = metrics(ds, rule_pred)
    report["per_category"]["rule_only"] = per_category_recall(ds, rule_pred)

    for lf in llm_files:
        data = json.loads(lf.read_text(encoding="utf-8"))
        model = data["model"]
        llm_pred = {}
        halluc = 0
        for v in data["verdicts"]:
            sid = v["sample_id"]
            llm_pred[sid] = bool(v.get("is_malicious"))
            # 근거 검증 재계산 (설명문+스키마)
            ok = verify_evidence(v.get("evidence_span", ""),
                                 ds[sid].get("description"),
                                 ds[sid].get("input_schema"))
            if ok is False:
                halluc += 1

        hybrid_pred = {sid: (rule_pred[sid] or llm_pred[sid]) for sid in ds}

        report["methods"][f"llm::{model}"] = {**metrics(ds, llm_pred),
                                              "evidence_hallucinations_corrected": halluc,
                                              "cost_krw": data.get("cost", {}).get("krw")}
        report["methods"][f"hybrid::{model}"] = metrics(ds, hybrid_pred)
        report["per_category"][f"llm::{model}"] = per_category_recall(ds, llm_pred)
        report["per_category"][f"hybrid::{model}"] = per_category_recall(ds, hybrid_pred)

    (RES / "comparison.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    # 출력
    print("=" * 68)
    print("방법별 성능 비교 (API 호출 없음)")
    print("=" * 68)
    print(f"  {'방법':<26} {'Prec':>6} {'Rec':>6} {'F1':>6} {'FPR':>6}")
    print("  " + "-" * 60)
    for name, m in report["methods"].items():
        print(f"  {name:<26} {m['precision']:>6.3f} {m['recall']:>6.3f} "
              f"{m['f1']:>6.3f} {m['fpr']:>6.3f}")
    print("  " + "-" * 60)
    # 환각 정정 안내
    for name, m in report["methods"].items():
        if "evidence_hallucinations_corrected" in m:
            print(f"  * {name}: 정정 후 실제 환각 {m['evidence_hallucinations_corrected']}건, "
                  f"비용 {m.get('cost_krw')}원")
    print("=" * 68)
    print(f"  저장: {RES / 'comparison.json'}")
    print("\n핵심: 규칙과 LLM 의 취약 지점이 상호보완적이라 하이브리드가 재현율을")
    print("      끌어올린다. (규칙=구조적 스키마 불일치 / LLM=의미적 은닉 지시)")


if __name__ == "__main__":
    main()
