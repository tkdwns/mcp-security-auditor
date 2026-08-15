"""모델 비교 실험 — Haiku 4.5 vs Sonnet 5 (전략 D 고정).

목적
----
"성능을 위해 꼭 비싼 모델이 필요한가?" 를 실측한다. 실무에서 반드시 나오는
비용-성능 트레이드오프 판단 능력을 보여주기 위함.

설계
----
- 데이터셋과 전략을 고정(홀드아웃 v2 + 전략 D)하고 **모델만 교체**한다.
  변수를 하나만 바꿔야 원인을 모델에 귀속시킬 수 있다.
- 이미 실행한 Sonnet 결과가 있으면 재사용해 비용을 아낀다(--reuse).
- 실행 후 **2단계 캐스케이드**를 시뮬레이션한다. 추가 API 호출 없이,
  저장된 두 모델의 per-sample 판정을 조합해 계산한다.

사용법
------
    python -m experiments.model_compare --dry-run
    python -m experiments.model_compare                      # Haiku 실행 + Sonnet 재사용
    python -m experiments.model_compare --models claude-opus-5   # 다른 모델 추가
"""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from pathlib import Path

from analyzer import console  # noqa: F401
from analyzer.llm_judge import CACHE_MIN_TOKENS, LLMJudge, PRICING, USD_TO_KRW
from analyzer.run import load_env
from .prompt_compare import stratified_sample, metrics, difficulty_recall, type_recall
from .strategies import make_catalog_strategy

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "data" / "benchmark"
OUT = ROOT / "data" / "results"

DEFAULT_MODELS = ["claude-haiku-4-5-20251001"]
SONNET = "claude-sonnet-5"
# Step 1 에서 이미 실행한 Sonnet + 전략 D 결과
SONNET_CACHE = OUT / "prompt_comparison_holdout_v2_only_D_catalog.json"


def cost_of(verdicts: list[dict], model: str) -> dict:
    """저장된 verdict 로부터 비용 계산.

    총 입력 = input_tokens + cache_creation + cache_read 이며 각각 단가가 다르다.
    (x1.0 / x1.25 / x0.1). input_tokens 는 이미 캐시분을 제외한 값이므로
    캐시 토큰을 다시 빼면 안 된다.
    """
    price = PRICING.get(model, {"in": 2.0, "out": 10.0})
    fresh = sum(v.get("input_tokens", 0) for v in verdicts)
    cache_w = sum(v.get("cache_creation_tokens", 0) for v in verdicts)
    cache_r = sum(v.get("cache_read_tokens", 0) for v in verdicts)
    out_tok = sum(v.get("output_tokens", 0) for v in verdicts)
    total_in = fresh + cache_w + cache_r
    usd = (fresh * price["in"] + cache_w * price["in"] * 1.25
           + cache_r * price["in"] * 0.1 + out_tok * price["out"]) / 1_000_000
    return {"input_tokens": fresh, "cache_creation_tokens": cache_w,
            "cache_read_tokens": cache_r, "output_tokens": out_tok,
            "total_input_tokens": total_in,
            "cache_hit_rate": round(cache_r / max(1, total_in), 3),
            "usd": round(usd, 4), "krw": round(usd * USD_TO_KRW, 1)}


def cascade_simulation(samples, per_model: dict, cheap: str, strong: str):
    """2단계 캐스케이드 시뮬레이션 (추가 API 호출 없음).

    규칙: 값싼 모델이 확신하면(conf >= t) 그 판정을 채택하고,
          확신이 낮으면(conf < t) 비싼 모델로 재검한다.
    임계값 t 를 바꿔가며 성능과 비용을 계산한다.
    """
    cheap_v = {v["sample_id"]: v for v in per_model[cheap]["verdicts"]}
    strong_v = {v["sample_id"]: v for v in per_model[strong]["verdicts"]}
    rows = []
    for t in [0.0, 0.6, 0.7, 0.8, 0.9, 0.95, 1.01]:
        preds, escalated = [], []
        cost_v = []
        for s in samples:
            sid = s["sample_id"]
            cv = cheap_v.get(sid)
            if cv is None:
                continue
            cost_v.append(("cheap", cv))
            if cv.get("confidence", 0) < t and sid in strong_v:
                sv = strong_v[sid]
                preds.append((s["is_malicious"], sv["is_malicious"]))
                cost_v.append(("strong", sv))
                escalated.append(sid)
            else:
                preds.append((s["is_malicious"], cv["is_malicious"]))
        m = metrics(preds)
        krw = (cost_of([v for tag, v in cost_v if tag == "cheap"], cheap)["krw"]
               + cost_of([v for tag, v in cost_v if tag == "strong"], strong)["krw"])
        rows.append({"threshold": t, "escalated": len(escalated),
                     "escalation_rate": round(len(escalated) / max(1, len(samples)), 3),
                     "metrics": m, "krw": round(krw, 1)})
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description="모델 비교 실험 (전략 D 고정)")
    ap.add_argument("--models", nargs="*", default=DEFAULT_MODELS)
    ap.add_argument("--sample", type=int, default=50)
    ap.add_argument("--cap", type=int, default=200)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-reuse", action="store_true",
                    help="Sonnet 결과를 재사용하지 않고 새로 호출")
    args = ap.parse_args()

    load_env(ROOT)

    bench = json.loads((BENCH / "dataset.json").read_text(encoding="utf-8"))
    catalog = {s["tool_name"] for s in bench["samples"] if not s["is_malicious"]}
    strat = make_catalog_strategy(catalog)

    ho = json.loads((BENCH / "holdout_v2.json").read_text(encoding="utf-8"))
    samples = stratified_sample(ho["samples"], args.sample) if args.sample else ho["samples"]

    models = list(args.models)
    per_model: dict[str, dict] = {}

    # --- Sonnet 결과 재사용 ---
    if not args.no_reuse and SONNET_CACHE.exists():
        cached = json.loads(SONNET_CACHE.read_text(encoding="utf-8"))
        d = cached["strategies"].get("D_catalog")
        if d:
            per_model[SONNET] = {"verdicts": d["verdicts"], "reused": True}
            print(f"[재사용] {SONNET} 결과를 Step 1 파일에서 불러옴 (추가 비용 0원)")
    if SONNET not in per_model and SONNET not in models:
        models.append(SONNET)

    print("=" * 70)
    print(f"모델 비교 [홀드아웃 v2 + 전략 D] — 표본 {len(samples)}건")
    print(f"신규 호출 모델: {models or '(없음)'}")
    if args.dry_run:
        print("[DRY-RUN] 호출 없음")
    print("=" * 70)

    for model in models:
        price = PRICING.get(model)
        est = len(samples) * (3.8 if "sonnet" in model else 1.9 if "haiku" in model else 9.5)
        print(f"\n▶ {model}" + (f"  (입력 ${price['in']}/M, 출력 ${price['out']}/M, "
                                f"예상 {est:.0f}원)" if price else ""))
        if args.dry_run:
            continue
        judge = LLMJudge(model=model, call_cap=args.cap)
        vs = []
        for i, s in enumerate(samples, 1):
            v = judge.judge(s, strategy=strat)
            vs.append(vars(v))
            if i % 10 == 0 or i == len(samples):
                print(f"    {i}/{len(samples)} 완료")
        per_model[model] = {"verdicts": vs, "reused": False}
        (OUT / f"llm_D_{model}.json").write_text(
            json.dumps({"model": model, "strategy": "D_catalog",
                        "dataset": "holdout_v2", "verdicts": vs},
                       ensure_ascii=False, indent=2), encoding="utf-8")

    if args.dry_run:
        print("\n[dry-run 완료]")
        return

    # --- 비교표 ---
    report = {"dataset": "holdout_v2", "strategy": "D_catalog",
              "n_samples": len(samples), "models": {}}
    for model, data in per_model.items():
        vmap = {v["sample_id"]: v for v in data["verdicts"]}
        subs = [s for s in samples if s["sample_id"] in vmap]
        pairs = [(s["is_malicious"], vmap[s["sample_id"]]["is_malicious"]) for s in subs]
        preds = [vmap[s["sample_id"]]["is_malicious"] for s in subs]
        m = metrics(pairs)
        c = cost_of(data["verdicts"], model)
        per100 = round(c["krw"] / max(1, len(subs)) * 100, 1)
        report["models"][model] = {
            "metrics": m, "cost": c, "krw_per_100_tools": per100,
            "f1_per_100won": round(m["f1"] / max(0.01, per100) * 100, 3),
            "difficulty_recall": difficulty_recall(subs, preds),
            "type_recall": type_recall(subs, preds),
            "reused": data["reused"],
        }

    print("\n" + "=" * 70)
    print("모델별 성능·비용")
    print("=" * 70)
    print(f"  {'모델':<30} {'Prec':>6} {'Rec':>6} {'F1':>6} {'FPR':>6} {'100건당':>9}")
    print("  " + "-" * 64)
    for model, r in report["models"].items():
        m = r["metrics"]
        print(f"  {model:<30} {m['precision']:>6.3f} {m['recall']:>6.3f} "
              f"{m['f1']:>6.3f} {m['fpr']:>6.3f} {r['krw_per_100_tools']:>8.0f}원")
    print("  " + "-" * 64)
    print("  [프롬프트 캐싱 진단]")
    for model, r in report["models"].items():
        hr = r["cost"].get("cache_hit_rate", 0)
        mark = "정상" if hr > 0.3 else "⚠️ 미적용"
        line = f"    {model:<30} 캐시적중 {hr*100:>5.1f}%  [{mark}]"
        print(line)
        if hr <= 0.01 and model in CACHE_MIN_TOKENS:
            print(f"      → 최소 캐시 길이 {CACHE_MIN_TOKENS[model]} 토큰 미달 시 "
                  f"캐싱이 조용히 건너뛰어짐(에러 없음). system 블록 길이를 확인하세요.")
    print("  [유형별 재현율]")
    for model, r in report["models"].items():
        print(f"    {model:<30} {r['type_recall']}")

    # --- 캐스케이드 ---
    cheap = next((m for m in report["models"] if "haiku" in m), None)
    if cheap and SONNET in report["models"]:
        rows = cascade_simulation(samples, per_model, cheap, SONNET)
        report["cascade"] = {"cheap": cheap, "strong": SONNET, "rows": rows}
        print("\n" + "=" * 70)
        print("2단계 캐스케이드 시뮬레이션 (추가 호출 없음)")
        print(f"  규칙: {cheap} 판정의 confidence < 임계값이면 {SONNET} 로 재검")
        print("=" * 70)
        print(f"  {'임계값':>7} {'재검율':>7} {'Prec':>6} {'Rec':>6} {'F1':>6} {'FPR':>6} {'비용':>8}")
        print("  " + "-" * 58)
        for r in rows:
            m = r["metrics"]
            t = "전부저가" if r["threshold"] == 0.0 else ("전부고가" if r["threshold"] > 1 else f"{r['threshold']:.2f}")
            print(f"  {t:>7} {r['escalation_rate']*100:>6.0f}% {m['precision']:>6.3f} "
                  f"{m['recall']:>6.3f} {m['f1']:>6.3f} {m['fpr']:>6.3f} {r['krw']:>7.0f}원")

    OUT.mkdir(parents=True, exist_ok=True)
    out = OUT / "model_comparison.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print("\n" + "=" * 70)
    print(f"  저장: {out}")


if __name__ == "__main__":
    main()
