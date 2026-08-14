"""LLM 판별기 실행 진입점.

사용법
------
    python -m analyzer.run --dry-run --limit 3   # 호출 없이 프롬프트 확인 (무료)
    python -m analyzer.run --limit 10            # 10건만 실제 호출 (수십 원)
    python -m analyzer.run                       # 전체 100건 (약 수백 원)
    python -m analyzer.run --model claude-haiku-4-5-20251001  # 저가 모델

안전장치: 총 호출 수 상한(--cap, 기본 120)을 넘으면 자동 중단.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from . import console  # noqa: F401  (UTF-8 콘솔)
from .llm_judge import LLMJudge

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET = PROJECT_ROOT / "data" / "benchmark" / "dataset.json"
OUT_DIR = PROJECT_ROOT / "data" / "results"


def load_env(project_root: Path) -> None:
    """.env 를 최소 파서로 로드 (python-dotenv 없이도 동작)."""
    env_path = project_root / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, val = line.split("=", 1)
        os.environ.setdefault(k.strip(), val.strip())


def confusion_and_metrics(rows):
    tp = fp = tn = fn = 0
    for actual, pred in rows:
        if pred and actual: tp += 1
        elif pred and not actual: fp += 1
        elif not pred and not actual: tn += 1
        else: fn += 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return dict(tp=tp, fp=fp, tn=tn, fn=fn,
               precision=round(prec, 4), recall=round(rec, 4),
               f1=round(f1, 4), fpr=round(fpr, 4))


def main() -> None:
    ap = argparse.ArgumentParser(description="LLM MCP 보안 판별기")
    ap.add_argument("--model", default=None, help="모델 ID (기본: .env 의 ANTHROPIC_MODEL)")
    ap.add_argument("--limit", type=int, default=None, help="앞에서 N건만 처리")
    ap.add_argument("--cap", type=int, default=120, help="총 호출 수 상한 (안전장치)")
    ap.add_argument("--dry-run", action="store_true", help="호출 없이 프롬프트만 출력")
    args = ap.parse_args()

    load_env(PROJECT_ROOT)
    model = args.model or os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5")

    if not DATASET.exists():
        raise SystemExit(f"[!] 데이터셋 없음: {DATASET}\n    먼저 python -m benchmark.build")

    data = json.loads(DATASET.read_text(encoding="utf-8"))
    samples = data["samples"]
    if args.limit:
        samples = samples[:args.limit]

    judge = LLMJudge(model=model, call_cap=args.cap)
    mode = "DRY-RUN (무료)" if args.dry_run else f"실제 호출 (model={model})"
    print("=" * 56)
    print(f"LLM 판별 시작 — {len(samples)}건 — {mode}")
    if not args.dry_run:
        print(f"안전장치: 호출 상한 {args.cap}건")
    print("=" * 56)

    verdicts = []
    for i, s in enumerate(samples, 1):
        v = judge.judge(s, dry_run=args.dry_run)
        verdicts.append(v)
        if not args.dry_run:
            mark = "!" if v.error else ("M" if v.is_malicious else ".")
            ev = ""
            if v.evidence_verified is False:
                ev = " [근거 미검증]"
            print(f"  [{i:3d}/{len(samples)}] {s['sample_id']:<14} "
                  f"{mark} conf={v.confidence:.2f} {v.owasp_code}{ev}"
                  + (f"  ERR:{v.error}" if v.error else ""))

    if args.dry_run:
        print("\n[dry-run 완료] 실제 호출 없음. 프롬프트가 의도대로면 --dry-run 빼고 재실행.")
        return

    # --- 성능 지표 (라벨과 대조) ---
    rows = [(s["is_malicious"], v.is_malicious)
            for s, v in zip(samples, verdicts) if v.error is None]
    metrics = confusion_and_metrics(rows)
    cost = judge.cost_krw(verdicts)
    n_hallucination = sum(1 for v in verdicts if v.evidence_verified is False)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    safe_model = model.replace(":", "_")
    out = OUT_DIR / f"llm_{safe_model}.json"
    out.write_text(json.dumps({
        "model": model,
        "n_samples": len(samples),
        "n_errors": sum(1 for v in verdicts if v.error),
        "metrics": metrics,
        "cost": cost,
        "evidence_hallucinations": n_hallucination,
        "verdicts": [vars(v) for v in verdicts],
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print("-" * 56)
    print("LLM 판별 성능")
    print(f"  Precision {metrics['precision']}  Recall {metrics['recall']}  "
          f"F1 {metrics['f1']}  FPR {metrics['fpr']}")
    print(f"  TP {metrics['tp']} FP {metrics['fp']} TN {metrics['tn']} FN {metrics['fn']}")
    print(f"  근거 미검증(환각 의심): {n_hallucination}건")
    print("-" * 56)
    print("비용")
    print(f"  입력 {cost['input_tokens']} (캐시 {cost['cache_read_tokens']}) / "
          f"출력 {cost['output_tokens']} 토큰")
    print(f"  ${cost['usd']}  ≈  {cost['krw']}원")
    print("-" * 56)
    print(f"  저장: {out}")


if __name__ == "__main__":
    main()
