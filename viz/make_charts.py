"""실험 결과 차트 생성 (API 호출 없음, 무료).

만드는 차트
-----------
1. f1_by_dataset.png    — 데이터셋 난이도별 방법 성능. "규칙은 붕괴, LLM은 유지"
2. recall_by_type.png   — 공격 유형별 재현율. "카탈로그가 섀도잉 사각지대를 해소"
3. model_tradeoff.png   — 모델별 성능/비용. "싼 모델이 더 비쌌다"

사용법:
    python -m viz.make_charts
"""

from __future__ import annotations

import json
from pathlib import Path

from analyzer import console  # noqa: F401
from analyzer.llm_judge import PRICING, USD_TO_KRW
from analyzer.rules import evaluate_sample
from . import theme
from .theme import MUTED, SERIES, TEXT_PRIMARY, TEXT_SECONDARY

import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "data" / "benchmark"
RES = ROOT / "data" / "results"
OUTDIR = RES / "charts"


# ----------------------------------------------------------------------
# 데이터 로딩 / 지표 계산
# ----------------------------------------------------------------------
def f1_of(pairs) -> float:
    tp = sum(1 for a, p in pairs if a and p)
    fp = sum(1 for a, p in pairs if not a and p)
    fn = sum(1 for a, p in pairs if a and not p)
    pr = tp / (tp + fp) if (tp + fp) else 0.0
    rc = tp / (tp + fn) if (tp + fn) else 0.0
    return 2 * pr * rc / (pr + rc) if (pr + rc) else 0.0


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def rule_f1(samples, known) -> float:
    return f1_of([(s["is_malicious"], evaluate_sample(s, known).rule_flag) for s in samples])


def strategy_f1(result_file: Path, key: str, sample_map) -> float | None:
    if not result_file.exists():
        return None
    d = load(result_file)
    r = d.get("strategies", {}).get(key)
    if not r:
        return None
    pairs = []
    for v in r["verdicts"]:
        s = sample_map.get(v["sample_id"])
        if s:
            pairs.append((s["is_malicious"], v["is_malicious"]))
    return f1_of(pairs) if pairs else None


# ----------------------------------------------------------------------
# 차트 1 — 데이터셋 난이도별 방법 성능
# ----------------------------------------------------------------------
def chart_f1_by_dataset(known):
    datasets = [
        ("Training set", BENCH / "dataset.json", RES / "prompt_comparison.json"),
        ("Hold-out v1", BENCH / "holdout.json", RES / "prompt_comparison_holdout.json"),
        ("Hold-out v2", BENCH / "holdout_v2.json", RES / "prompt_comparison_holdout_v2.json"),
    ]
    labels, rules, zs, fs = [], [], [], []
    for label, ds_path, res_path in datasets:
        samples = load(ds_path)["samples"]
        smap = {s["sample_id"]: s for s in samples}
        # 규칙은 결과 파일에 쓰인 표본과 맞추기 위해, 결과가 있으면 그 표본만 사용
        sub = samples
        if res_path.exists():
            d = load(res_path)
            k = next(iter(d["strategies"]))
            ids = {v["sample_id"] for v in d["strategies"][k]["verdicts"]}
            sub = [s for s in samples if s["sample_id"] in ids]
        labels.append(label)
        rules.append(rule_f1(sub, known))
        zs.append(strategy_f1(res_path, "A_zeroshot", smap) or 0.0)
        fs.append(strategy_f1(res_path, "B_fewshot", smap) or 0.0)

    x = np.arange(len(labels))
    w = 0.26
    fig, ax = plt.subplots(figsize=(7.6, 4.2))
    b1 = ax.bar(x - w, rules, w * 0.92, label="Rule engine", color=SERIES[0])
    b2 = ax.bar(x, zs, w * 0.92, label="LLM (zero-shot)", color=SERIES[1])
    b3 = ax.bar(x + w, fs, w * 0.92, label="LLM (few-shot)", color=SERIES[2])
    for b in (b1, b2, b3):
        theme.bar_labels(ax, b)

    ax.set_ylim(0, 1.16)
    ax.set_ylabel("F1 score")
    ax.set_xticks(x, labels)
    # 제목은 pad 로 위로 띄우고, 부제는 축 바로 위(1.015)에 둔다.
    # (부제를 1.08 에 두면 제목보다 위로 올라가 겹친다 — 렌더 확인으로 발견)
    ax.set_title("Rules collapse on unseen phrasings; the LLM holds",
                 fontsize=12.5, color=TEXT_PRIMARY, pad=30, loc="left")
    ax.text(0, 1.015, "Same attacks, new wording. Hold-out v2 is difficulty-matched.",
            transform=ax.transAxes, fontsize=9, color=TEXT_SECONDARY, va="bottom")
    theme.clean_axes(ax)
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.1),
              ncol=3, fontsize=9.5)
    fig.tight_layout()
    out = OUTDIR / "f1_by_dataset.png"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    return out


# ----------------------------------------------------------------------
# 차트 2 — 공격 유형별 재현율 (B vs D)
# ----------------------------------------------------------------------
def chart_recall_by_type():
    samples = {s["sample_id"]: s for s in load(BENCH / "holdout_v2.json")["samples"]}
    abc = load(RES / "prompt_comparison_holdout_v2.json")["strategies"]
    dfile = RES / "prompt_comparison_holdout_v2_only_D_catalog.json"
    d = load(dfile)["strategies"]["D_catalog"]

    types = ["hidden_instruction", "schema_mismatch", "scope_creep", "tool_shadowing"]
    nice = ["Hidden\ninstruction", "Schema\nmismatch", "Scope\ncreep", "Tool\nshadowing"]

    def recall_by_type(verdicts):
        tot = {t: 0 for t in types}
        hit = {t: 0 for t in types}
        for v in verdicts:
            s = samples.get(v["sample_id"])
            if not s or not s["is_malicious"]:
                continue
            t = s["attack_type"]
            tot[t] += 1
            if v["is_malicious"]:
                hit[t] += 1
        return [hit[t] / tot[t] if tot[t] else 0.0 for t in types], [tot[t] for t in types]

    rb, counts = recall_by_type(abc["B_fewshot"]["verdicts"])
    rd, _ = recall_by_type(d["verdicts"])

    x = np.arange(len(types))
    w = 0.36
    fig, ax = plt.subplots(figsize=(7.6, 4.2))
    b1 = ax.bar(x - w / 2, rb, w * 0.94, label="B: few-shot", color=SERIES[0])
    b2 = ax.bar(x + w / 2, rd, w * 0.94, label="D: few-shot + catalog", color=SERIES[1])
    theme.bar_labels(ax, b1, fmt="{:.2f}")
    theme.bar_labels(ax, b2, fmt="{:.2f}")

    # 사각지대 해소 지점을 표시
    ax.annotate("blind spot fixed\n0.00 → 1.00",
                xy=(3 + w / 2, 1.0), xytext=(2.55, 0.62),
                fontsize=9, color=TEXT_SECONDARY,
                arrowprops=dict(arrowstyle="->", color=MUTED, lw=1.2))

    ax.set_ylim(0, 1.22)
    ax.set_ylabel("Recall")
    ax.set_xticks(x, nice)
    ax.set_title("Tool shadowing was an input-design problem, not a prompt problem",
                 fontsize=12.5, color=TEXT_PRIMARY, pad=30, loc="left")
    ax.text(0, 1.015,
            "Hold-out v2. The trusted tool-name catalog fixed shadowing "
            "without hurting other types.",
            transform=ax.transAxes, fontsize=9, color=TEXT_SECONDARY, va="bottom")
    theme.clean_axes(ax)
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.12),
              ncol=2, fontsize=9.5)
    fig.tight_layout()
    out = OUTDIR / "recall_by_type.png"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    return out


# ----------------------------------------------------------------------
# 차트 3 — 모델 성능/비용 (small multiples, 이중축 금지)
# ----------------------------------------------------------------------
def cost_per_100(verdicts, model) -> float:
    """수정된 공식으로 100건당 비용을 재계산.

    model_comparison.json 에 저장된 krw_per_100_tools 는 비용 버그 수정 **이전**
    공식으로 계산된 값이라 그대로 쓰면 안 된다. 원본 토큰 수에서 다시 계산한다.
    """
    p = PRICING.get(model, {"in": 2.0, "out": 10.0})
    fi = sum(v.get("input_tokens", 0) for v in verdicts)
    cw = sum(v.get("cache_creation_tokens", 0) for v in verdicts)
    cr = sum(v.get("cache_read_tokens", 0) for v in verdicts)
    ot = sum(v.get("output_tokens", 0) for v in verdicts)
    usd = (fi * p["in"] + cw * p["in"] * 1.25 + cr * p["in"] * 0.1
           + ot * p["out"]) / 1_000_000
    return usd * USD_TO_KRW / max(1, len(verdicts)) * 100


def chart_model_tradeoff():
    d = load(RES / "model_comparison.json")
    order = ["claude-sonnet-5", "claude-haiku-4-5-20251001"]
    order = [m for m in order if m in d["models"]]
    short = {"claude-sonnet-5": "Sonnet 5", "claude-haiku-4-5-20251001": "Haiku 4.5"}
    f1s = [d["models"][m]["metrics"]["f1"] for m in order]

    # 원본 verdict 파일에서 토큰을 읽어 비용 재계산
    raw_files = {
        "claude-sonnet-5": RES / "prompt_comparison_holdout_v2_only_D_catalog.json",
        "claude-haiku-4-5-20251001": RES / "llm_D_claude-haiku-4-5-20251001.json",
    }
    costs = []
    for m in order:
        f = raw_files.get(m)
        vs = None
        if f and f.exists():
            data = load(f)
            vs = (data.get("strategies", {}).get("D_catalog", {}).get("verdicts")
                  or data.get("verdicts"))
        if vs:
            costs.append(round(cost_per_100(vs, m)))
        else:  # 원본이 없으면 저장값으로 폴백 (구 공식일 수 있음)
            costs.append(d["models"][m]["krw_per_100_tools"])
    # emphasis: 채택 모델만 강조, 나머지는 gray
    colors = [SERIES[0] if m == "claude-sonnet-5" else MUTED for m in order]
    names = [short.get(m, m) for m in order]

    fig, axes = plt.subplots(1, 2, figsize=(7.8, 3.9))
    for ax, vals, title, fmt, pad in [
        (axes[0], f1s, "Detection quality (F1)", "{:.3f}", 0.08),
        (axes[1], costs, "Cost per 100 tools (KRW)", "{:.0f}", 60),
    ]:
        bars = ax.bar(names, vals, 0.5, color=colors)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + pad * 0.15, fmt.format(v),
                    ha="center", va="bottom", fontsize=9.5, color=TEXT_SECONDARY)
        ax.set_ylim(0, max(vals) * 1.25)
        ax.set_title(title, fontsize=10.5, color=TEXT_PRIMARY, loc="left", pad=8)
        theme.clean_axes(ax)

    fig.tight_layout(rect=(0, 0, 1, 0.86))
    fig.suptitle("The cheaper model was both worse and more expensive",
                 fontsize=12.5, color=TEXT_PRIMARY, x=0.015, ha="left", y=0.99)
    fig.text(0.015, 0.90,
             "Haiku 4.5 fell below its 4,096-token prompt-cache minimum, "
             "so caching was silently skipped.",
             fontsize=9, color=TEXT_SECONDARY, ha="left")
    out = OUTDIR / "model_tradeoff.png"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    return out


def main() -> None:
    theme.apply_base_style()
    OUTDIR.mkdir(parents=True, exist_ok=True)
    bench = load(BENCH / "dataset.json")["samples"]
    known = {s["tool_name"] for s in bench if not s["is_malicious"]}

    outs = [chart_f1_by_dataset(known), chart_recall_by_type(), chart_model_tradeoff()]
    print("=" * 60)
    print("차트 생성 완료 (API 호출 없음)")
    print("=" * 60)
    for o in outs:
        print(f"  {o}")
    print("=" * 60)
    print("  README 및 발표자료에 그대로 삽입 가능합니다.")


if __name__ == "__main__":
    main()
