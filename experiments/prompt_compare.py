"""프롬프트 전략 3종 비교 실험.

사용법
------
    python -m experiments.prompt_compare --dry-run          # 무료. 프롬프트 확인
    python -m experiments.prompt_compare --sample 50        # 층화표본 50건 (권장, 저비용)
    python -m experiments.prompt_compare                    # 전체 100건 x 3전략
    python -m experiments.prompt_compare --only B_fewshot   # 특정 전략만

비용 관리
---------
전략 3종 x N건 = 3N 호출이다. --sample 로 층화표본을 쓰면 비용이 준다.
층화표본은 정상/공격유형/난이도 비율을 원본과 같게 유지해 통계적 대표성을 지킨다.
호출 상한(--cap)은 안전장치로 항상 걸린다.
"""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from pathlib import Path

from analyzer import console  # noqa: F401
from analyzer.llm_judge import LLMJudge, verify_evidence
from analyzer.rules import evaluate_sample
from analyzer.run import load_env
from .strategies import STRATEGIES, make_catalog_strategy

ROOT = Path(__file__).resolve().parent.parent
DS = ROOT / "data" / "benchmark" / "dataset.json"
OUT = ROOT / "data" / "results"


def stratified_sample(samples: list[dict], n: int) -> list[dict]:
    """정상/공격유형/난이도 비율을 유지하며 n건을 고른다.

    무작위가 아니라 각 층에서 균등 간격으로 뽑아 재현성을 보장한다.
    (같은 명령을 다시 실행해도 같은 표본 → 실험 비교가 가능)
    """
    if n >= len(samples):
        return samples
    strata: dict[str, list[dict]] = defaultdict(list)
    for s in samples:
        key = "clean" if not s["is_malicious"] else f"{s['attack_type']}/{s['difficulty']}"
        strata[key].append(s)

    total = len(samples)
    picked: list[dict] = []
    for key in sorted(strata):
        group = strata[key]
        take = max(1, round(len(group) * n / total))
        step = len(group) / take
        for i in range(take):
            picked.append(group[int(i * step)])
    # sample_id 순으로 정렬해 출력 안정화
    picked.sort(key=lambda x: x["sample_id"])
    return picked


def metrics(pairs):
    tp = fp = tn = fn = 0
    for actual, pred in pairs:
        if pred and actual: tp += 1
        elif pred and not actual: fp += 1
        elif not pred and not actual: tn += 1
        else: fn += 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return dict(precision=round(prec, 4), recall=round(rec, 4),
                f1=round(f1, 4), fpr=round(fpr, 4), tp=tp, fp=fp, tn=tn, fn=fn)


def difficulty_recall(samples, preds):
    tot = defaultdict(int); hit = defaultdict(int)
    for s, p in zip(samples, preds):
        if s["is_malicious"]:
            tot[s["difficulty"]] += 1
            if p: hit[s["difficulty"]] += 1
    return {d: f"{hit[d]}/{tot[d]}" for d in ["easy", "medium", "hard"] if tot[d]}


def type_recall(samples, preds):
    tot = defaultdict(int); hit = defaultdict(int)
    for s, p in zip(samples, preds):
        if s["is_malicious"]:
            tot[s["attack_type"]] += 1
            if p: hit[s["attack_type"]] += 1
    return {t: f"{hit[t]}/{tot[t]}" for t in sorted(tot)}


def main() -> None:
    ap = argparse.ArgumentParser(description="프롬프트 전략 비교 실험")
    ap.add_argument("--model", default=None)
    ap.add_argument("--sample", type=int, default=None, help="층화표본 크기 (미지정 시 전체)")
    ap.add_argument("--cap", type=int, default=350, help="총 호출 상한 (안전장치)")
    ap.add_argument("--only", default=None,
                    help="특정 전략만 (A_zeroshot/B_fewshot/C_rulehint/D_catalog)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--dataset", default="benchmark",
                    choices=["benchmark", "holdout", "holdout_v2"],
                    help="benchmark=학습셋 / holdout=신규표현 / holdout_v2=난이도 대응")
    ap.add_argument("--tag", default=None, help="결과 파일명 접미사")
    args = ap.parse_args()

    load_env(ROOT)
    model = args.model or os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5")

    ds_files = {"benchmark": "dataset.json", "holdout": "holdout.json",
                "holdout_v2": "holdout_v2.json"}
    ds_path = DS.parent / ds_files[args.dataset]
    if not ds_path.exists():
        raise SystemExit(f"[!] 데이터셋 없음: {ds_path}\n"
                         f"    holdout 은 python -m benchmark.build_holdout 로 먼저 생성")
    data = json.loads(ds_path.read_text(encoding="utf-8"))
    samples = data["samples"]
    if args.sample:
        samples = stratified_sample(samples, args.sample)

    # 전략 D(카탈로그 인지)는 신뢰된 도구명 목록이 필요하므로 런타임에 만든다.
    # 카탈로그 = 원본 벤치마크의 정상 도구명 집합 (= 검증을 마친 신뢰 서버의 도구들).
    benchmark_clean = {
        s["tool_name"]
        for s in json.loads(DS.read_text(encoding="utf-8"))["samples"]
        if not s["is_malicious"]
    }
    all_strategies = dict(STRATEGIES)
    all_strategies["D_catalog"] = make_catalog_strategy(benchmark_clean)

    keys = [args.only] if args.only else list(STRATEGIES)  # 기본은 A/B/C
    n_calls = len(samples) * len(keys)

    print("=" * 66)
    labels = {"benchmark": "학습셋(benchmark)",
              "holdout": "★홀드아웃 v1 (신규 표현)★",
              "holdout_v2": "★홀드아웃 v2 (난이도 대응)★"}
    label = labels[args.dataset]
    print(f"프롬프트 전략 비교 [{label}] — "
          f"표본 {len(samples)}건 x 전략 {len(keys)}종 = {n_calls} 호출")
    print(f"모델: {model}" + ("   [DRY-RUN 무료]" if args.dry_run else ""))
    if not args.dry_run:
        est = n_calls * 4.9  # 2주차 실측: 100건 491원 기준 1건당 약 4.9원
        print(f"예상 비용: 약 {est:.0f}원 (2주차 실측 기준. 캐시 적중 시 더 낮아짐)")
    print("=" * 66)

    # 규칙 힌트 사전 계산 (전략 C 용). LLM 호출 아님, 무료.
    # 알려진 정상 도구명 카탈로그는 항상 원본 벤치마크의 clean 집합을 쓴다.
    known = {s["tool_name"] for s in data["samples"] if not s["is_malicious"]}
    rule_hints = {}
    for s in samples:
        r = evaluate_sample(s, known)
        rule_hints[s["sample_id"]] = r.to_row()

    judge = LLMJudge(model=model, call_cap=args.cap)
    report = {"model": model, "dataset": args.dataset,
              "n_samples": len(samples), "strategies": {}}

    for key in keys:
        strat = all_strategies[key]
        print(f"\n▶ {strat.label}")
        verdicts = []
        for i, s in enumerate(samples, 1):
            hint = rule_hints[s["sample_id"]] if strat.needs_rule_hint else None
            if args.dry_run:
                if i == 1:  # 전략당 첫 건만 프롬프트 미리보기
                    print("--- 프롬프트 미리보기 (system 앞 200자) ---")
                    print(strat.system_text[:200].replace("\n", " ") + " ...")
                    print("--- user ---")
                    print(strat.build_user(s, hint)[:700])
                continue
            v = judge.judge(s, strategy=strat, rule_hint=hint)
            verdicts.append(v)
            if i % 10 == 0 or i == len(samples):
                print(f"    {i}/{len(samples)} 완료")

        if args.dry_run:
            continue

        ok = [(s, v) for s, v in zip(samples, verdicts) if v.error is None]
        pairs = [(s["is_malicious"], v.is_malicious) for s, v in ok]
        preds = [v.is_malicious for s, v in ok]
        subs = [s for s, v in ok]
        halluc = sum(
            1 for s, v in ok
            if verify_evidence(v.evidence_span, s.get("description"), s.get("input_schema")) is False
        )
        m = metrics(pairs)
        cost = judge.cost_krw(verdicts)
        report["strategies"][key] = {
            "label": strat.label, "metrics": m, "cost": cost,
            "difficulty_recall": difficulty_recall(subs, preds),
            "type_recall": type_recall(subs, preds),
            "evidence_hallucinations": halluc,
            "errors": sum(1 for v in verdicts if v.error),
            "verdicts": [vars(v) for v in verdicts],
        }
        print(f"    → P{m['precision']:.3f} R{m['recall']:.3f} F1{m['f1']:.3f} "
              f"FPR{m['fpr']:.3f}  ({cost['krw']}원)")

    if args.dry_run:
        print("\n[dry-run 완료] 실제 호출 없음.")
        return

    OUT.mkdir(parents=True, exist_ok=True)
    # 파일명 규칙
    #   전체 실행        -> prompt_comparison[_dataset].json
    #   --only 단일 전략 -> ..._only_<전략키>.json  (전체 실행 결과를 덮어쓰지 않도록)
    # (이 분기가 없던 초기 버전은 --only 실행이 직전 전체 결과를 통째로 덮어썼다)
    suffix = {"benchmark": "", "holdout": "_holdout",
              "holdout_v2": "_holdout_v2"}[args.dataset]
    if args.tag:
        suffix += f"_{args.tag}"
    elif args.only:
        suffix += f"_only_{args.only}"
    out = OUT / f"prompt_comparison{suffix}.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    # --- 최종 표 ---
    print("\n" + "=" * 66)
    print("프롬프트 전략 비교 결과")
    print("=" * 66)
    print(f"  {'전략':<22} {'Prec':>6} {'Rec':>6} {'F1':>6} {'FPR':>6} {'비용':>8}")
    print("  " + "-" * 58)
    for key in keys:
        if key not in report["strategies"]: continue
        r = report["strategies"][key]; m = r["metrics"]
        print(f"  {r['label']:<22} {m['precision']:>6.3f} {m['recall']:>6.3f} "
              f"{m['f1']:>6.3f} {m['fpr']:>6.3f} {r['cost']['krw']:>7.0f}원")
    print("  " + "-" * 58)
    print("  [난이도별 재현율]")
    for key in keys:
        if key not in report["strategies"]: continue
        r = report["strategies"][key]
        print(f"    {r['label']:<22} {r['difficulty_recall']}")
    print("  [유형별 재현율]")
    for key in keys:
        if key not in report["strategies"]: continue
        r = report["strategies"][key]
        print(f"    {r['label']:<22} {r['type_recall']}")
    print("=" * 66)
    print(f"  저장: {out}")


if __name__ == "__main__":
    main()
