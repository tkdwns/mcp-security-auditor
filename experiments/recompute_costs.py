"""저장된 모든 실험 결과의 비용을 수정된 공식으로 재계산한다.

배경
----
초기 비용 계산에 두 가지 오류가 있었다.
  1. `fresh = input_tokens - cache_read` 로 이중 차감했다.
     Anthropic 의 `input_tokens` 는 이미 캐시분을 제외한 값이다.
  2. `cache_creation_input_tokens`(기본가 x1.25)를 누락했다.

결과적으로 캐시가 잘 듣는 모델의 비용을 과소 보고했다.
이 스크립트는 API 호출 없이 저장된 토큰 수만으로 전부 재계산한다(무료).

사용법:
    python -m experiments.recompute_costs
"""

from __future__ import annotations

import json
from pathlib import Path

from analyzer import console  # noqa: F401
from analyzer.llm_judge import CACHE_MIN_TOKENS, PRICING, USD_TO_KRW

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "data" / "results"


def cost(verdicts, model):
    p = PRICING.get(model, {"in": 2.0, "out": 10.0})
    fi = sum(v.get("input_tokens", 0) for v in verdicts)
    cw = sum(v.get("cache_creation_tokens", 0) for v in verdicts)
    cr = sum(v.get("cache_read_tokens", 0) for v in verdicts)
    ot = sum(v.get("output_tokens", 0) for v in verdicts)
    usd = (fi * p["in"] + cw * p["in"] * 1.25 + cr * p["in"] * 0.1
           + ot * p["out"]) / 1_000_000
    total_in = fi + cw + cr
    return {"n": len(verdicts), "fresh_in": fi, "cache_w": cw, "cache_r": cr,
            "out": ot, "cache_hit_rate": round(cr / max(1, total_in), 3),
            "usd": round(usd, 4), "krw": round(usd * USD_TO_KRW, 1)}


def old_cost(verdicts, model):
    """비교용: 버그가 있던 옛 공식."""
    p = PRICING.get(model, {"in": 2.0, "out": 10.0})
    fi = sum(v.get("input_tokens", 0) for v in verdicts)
    cr = sum(v.get("cache_read_tokens", 0) for v in verdicts)
    ot = sum(v.get("output_tokens", 0) for v in verdicts)
    usd = (max(0, fi - cr) * p["in"] + cr * p["in"] * 0.1 + ot * p["out"]) / 1_000_000
    return round(usd * USD_TO_KRW, 1)


def collect():
    """결과 파일들에서 (라벨, 모델, verdicts) 를 뽑아낸다."""
    items = []
    for f in sorted(RES.glob("*.json")):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if "strategies" in d:  # prompt_comparison*
            for k, r in d["strategies"].items():
                if "verdicts" in r:
                    items.append((f"{f.stem} :: {k}", d.get("model", "claude-sonnet-5"),
                                  r["verdicts"]))
        elif "models" in d:  # model_comparison (verdicts 미포함)
            continue
        elif "verdicts" in d:  # llm_*.json
            items.append((f.stem, d.get("model", "claude-sonnet-5"), d["verdicts"]))
    return items


def main() -> None:
    items = collect()
    if not items:
        raise SystemExit("[!] 재계산할 결과 파일이 없습니다.")

    print("=" * 84)
    print("비용 재계산 (수정된 공식) — API 호출 없음")
    print("=" * 84)
    print(f"  {'실험':<46} {'건수':>4} {'캐시적중':>7} {'구버전':>8} {'수정후':>8}")
    print("  " + "-" * 78)
    tot_old = tot_new = 0.0
    for label, model, vs in items:
        c = cost(vs, model)
        o = old_cost(vs, model)
        tot_old += o
        tot_new += c["krw"]
        print(f"  {label:<46} {c['n']:>4} {c['cache_hit_rate']*100:>6.0f}% "
              f"{o:>7.0f}원 {c['krw']:>7.0f}원")
    print("  " + "-" * 78)
    print(f"  {'합계':<46} {'':>4} {'':>7} {tot_old:>7.0f}원 {tot_new:>7.0f}원")
    print(f"  → 과소 보고분: {tot_new - tot_old:.0f}원 ({(tot_new/max(1,tot_old)-1)*100:.0f}% 상향)")

    # --- 캐시 미적용 경고 ---
    print("\n" + "=" * 84)
    print("프롬프트 캐싱 진단")
    print("=" * 84)
    seen = {}
    for label, model, vs in items:
        c = cost(vs, model)
        seen.setdefault(model, []).append(c["cache_hit_rate"])
    for model, rates in seen.items():
        avg = sum(rates) / len(rates)
        minimum = CACHE_MIN_TOKENS.get(model)
        status = "정상" if avg > 0.3 else "⚠️ 캐싱 미적용"
        print(f"  {model:<32} 평균 캐시적중률 {avg*100:>5.1f}%  [{status}]")
        if avg <= 0.01 and minimum:
            print(f"      → 이 모델의 최소 캐시 가능 길이는 {minimum} 토큰입니다.")
            print(f"        system 블록이 그보다 짧으면 캐싱이 '조용히' 건너뛰어집니다(에러 없음).")
            print(f"        해결: system 블록을 {minimum} 토큰 이상으로 늘리면 캐싱이 활성화됩니다.")

    out = RES / "cost_recomputed.json"
    out.write_text(json.dumps(
        {"note": "수정된 공식으로 재계산. input_tokens 이중차감 제거 + cache_creation x1.25 반영",
         "items": [{"label": l, "model": m, **cost(v, m), "old_krw": old_cost(v, m)}
                   for l, m, v in items]},
        ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n  저장: {out}")


if __name__ == "__main__":
    main()
