"""MCP 서버 보안 감사 리포트 생성기 — 프로젝트 최종 산출물.

전체 파이프라인을 하나로 연결한다:
    수집 → 규칙 엔진 → LLM 판별(전략 D) → 심각도 산정 → 자연어 리포트

사용법
------
    # 수집본에서 특정 서버 감사 (권장 — 이미 수집한 데이터 재사용)
    python -m report.generate --server filesystem

    # 모든 서버 감사
    python -m report.generate --all

    # 데모 리포트 3종 (정상 / 위험 / 혼합) — 포트폴리오 샘플용
    python -m report.generate --demo clean
    python -m report.generate --demo poisoned
    python -m report.generate --demo mixed

    # 호출 없이 대상만 확인
    python -m report.generate --server filesystem --dry-run

산출물
------
    reports/<name>_<stamp>.md    사람이 읽는 감사 리포트
    reports/<name>_<stamp>.json  기계 판독용 원본 결과
"""

from __future__ import annotations

import argparse
import json
import os
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from analyzer import console  # noqa: F401
from analyzer.llm_judge import LLMJudge, verify_evidence
from analyzer.rules import evaluate_sample
from analyzer.run import load_env
from experiments.strategies import make_catalog_strategy
from .severity import SEVERITY_ORDER, assess, overall_grade, owasp_label

KST = timezone(timedelta(hours=9))
ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw" / "_latest.json"
BENCH = ROOT / "data" / "benchmark"
OUTDIR = ROOT / "reports"

MODEL_DEFAULT = "claude-sonnet-5"


# ----------------------------------------------------------------------
# 감사 대상 구성
# ----------------------------------------------------------------------
def tools_from_raw(server: str | None) -> tuple[str, list[dict]]:
    if not RAW.exists():
        raise SystemExit(f"[!] 수집본이 없습니다: {RAW}\n    먼저 python -m collector.run")
    data = json.loads(RAW.read_text(encoding="utf-8"))
    out = []
    for sv in data.get("servers", []):
        if sv.get("status") != "ok":
            continue
        if server and sv["server_name"] != server:
            continue
        for t in sv.get("tools", []):
            out.append({
                "sample_id": f"{sv['server_name']}::{t['tool_name']}",
                "source_server": sv["server_name"],
                "tool_name": t["tool_name"],
                "description": t.get("description"),
                "input_schema": t.get("input_schema", {}),
            })
    if not out:
        raise SystemExit(f"[!] 대상 도구가 없습니다 (server={server}).")
    return (server or "all-servers"), out


def tools_from_demo(kind: str) -> tuple[str, list[dict]]:
    """포트폴리오용 데모 리포트 대상.

    ⚠️ 오염 샘플은 탐지 성능 평가를 위한 **합성 데이터**이며, 동작하는 악성
       MCP 서버가 아니다. 실제로 배포되지 않는다.
    """
    ho = json.loads((BENCH / "holdout_v2.json").read_text(encoding="utf-8"))["samples"]
    clean = [s for s in ho if not s["is_malicious"] and s["source_server"] == "filesystem"]

    # 오염 샘플은 공격 유형별로 고르게 뽑는다.
    # (단순히 앞에서 N개를 자르면 hidden_instruction 만 10건 나온다 —
    #  데이터셋이 유형별로 정렬되어 있기 때문. 실제로 첫 데모가 그랬다.)
    by_type: dict[str, list[dict]] = {}
    for s in ho:
        if s["is_malicious"]:
            by_type.setdefault(s["attack_type"], []).append(s)
    poison = []
    for k in range(max(len(v) for v in by_type.values())):
        for t in sorted(by_type):
            if k < len(by_type[t]):
                poison.append(by_type[t][k])
    if kind == "clean":
        picked, name = clean[:12], "demo-clean-server"
    elif kind == "poisoned":
        picked, name = poison[:10], "demo-malicious-server"
    else:
        picked, name = clean[:8] + poison[:6], "demo-mixed-server"
    out = []
    for s in picked:
        out.append({
            "sample_id": s["sample_id"], "source_server": name,
            "tool_name": s["tool_name"], "description": s["description"],
            "input_schema": s["input_schema"],
            "_truth": s["is_malicious"],  # 데모에서만: 정답 표시용
        })
    return name, out


# ----------------------------------------------------------------------
# 감사 실행
# ----------------------------------------------------------------------
def audit(tools: list[dict], model: str, catalog: set[str], cap: int) -> dict:
    judge = LLMJudge(model=model, call_cap=cap)
    strat = make_catalog_strategy(catalog)
    findings, safe, notes, verdicts = [], [], [], []
    t0 = time.time()

    for i, t in enumerate(tools, 1):
        rule = evaluate_sample(t, catalog)
        v = judge.judge(t, strategy=strat)
        verdicts.append(v)
        print(f"  [{i:3d}/{len(tools)}] {t['tool_name']:<28} "
              f"{'위험' if v.is_malicious else '정상'}"
              + (f"  ERR:{v.error}" if v.error else ""))

        if v.error:
            continue
        if v.is_malicious:
            detected_by = "both" if rule.rule_flag else "llm"
        elif rule.rule_flag:
            # 규칙만 반응하고 LLM 은 정상으로 판정한 경우.
            # 이것을 '발견된 위험'에 넣으면 안 된다:
            #   · 홀드아웃 v2 에서 규칙의 고유 탐지 기여도는 0으로 측정되었고
            #   · 규칙 단독 정밀도가 낮아 정상 서버에 오탐을 만든다.
            # 실제로 공식 filesystem 서버 감사 시 'succeed silently'(조용히 성공)
            # 라는 무해한 표현이 은폐 표현 규칙에 걸려 판정이 '적합'에서
            # '검토 필요'로 내려갔다. 투명성을 위해 기록은 남기되,
            # 위험 목록과 종합 판정에서는 제외한다.
            notes.append({
                "tool_name": t["tool_name"],
                "rule_signals": [h.rule_id for h in rule.hits],
                "details": [h.detail for h in rule.hits],
            })
            safe.append({"tool_name": t["tool_name"],
                         "description": (t.get("description") or "")[:120]})
            continue
        else:
            safe.append({"tool_name": t["tool_name"],
                         "description": (t.get("description") or "")[:120]})
            continue
        detected_by = detected_by

        level, action = assess(v.attack_type, v.confidence, detected_by)
        findings.append({
            "tool_name": t["tool_name"],
            "server": t["source_server"],
            "severity": level,
            "owasp": owasp_label(v.owasp_code),
            "attack_type": v.attack_type,
            "confidence": v.confidence,
            "detected_by": detected_by,
            "evidence": v.evidence_span,
            "evidence_verified": verify_evidence(
                v.evidence_span, t.get("description"), t.get("input_schema")),
            "reasoning": v.reasoning,
            "action": action,
            "rule_signals": [h.rule_id for h in rule.hits],
            "_truth": t.get("_truth"),
        })

    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), -f["confidence"]))
    elapsed = time.time() - t0
    return {"findings": findings, "safe": safe, "notes": notes, "verdicts": verdicts,
            "elapsed_sec": round(elapsed, 1), "cost": judge.cost_krw(verdicts),
            "model": model, "n_tools": len(tools)}


# ----------------------------------------------------------------------
# 리포트 렌더링
# ----------------------------------------------------------------------
def render_markdown(name: str, res: dict, demo: bool) -> str:
    stamp = datetime.now(KST).strftime("%Y-%m-%d %H:%M")
    counts = Counter(f["severity"] for f in res["findings"])
    grade, verdict = overall_grade(counts)
    c = res["cost"]

    L = []
    L.append(f"# MCP 서버 보안 감사 리포트 — `{name}`\n")
    L.append(f"| 항목 | 값 |\n|---|---|")
    L.append(f"| 감사 일시 | {stamp} (KST) |")
    L.append(f"| 검사 대상 | 도구 {res['n_tools']}개 |")
    L.append(f"| 판별 모델 | `{res['model']}` (전략 D: few-shot + 카탈로그) |")
    L.append(f"| 소요 시간 | {res['elapsed_sec']}초 |")
    L.append(f"| 판별 비용 | {c['krw']}원 (캐시적중 {c['cache_hit_rate']*100:.0f}%) |")
    L.append(f"| **종합 판정** | **{grade}** |\n")
    L.append(f"> {verdict}\n")

    # 위험 등급 분포
    L.append("## 1. 요약\n")
    L.append("| 등급 | 건수 |\n|---|---|")
    for lv in SEVERITY_ORDER:
        if counts.get(lv):
            L.append(f"| {lv} | {counts[lv]} |")
    L.append(f"| 이상 없음 | {len(res['safe'])} |")
    if res.get("notes"):
        L.append(f"| (참고) 규칙만 반응 | {len(res['notes'])} |")
    L.append("")

    # 상세 발견
    L.append("## 2. 발견된 위험\n")
    if not res["findings"]:
        L.append("탐지된 위험이 없습니다.\n")
    for i, f in enumerate(res["findings"], 1):
        L.append(f"### {i}. `{f['tool_name']}` — {f['severity']}\n")
        L.append(f"| | |\n|---|---|")
        L.append(f"| OWASP | {f['owasp']} |")
        L.append(f"| 공격 유형 | {f['attack_type']} |")
        L.append(f"| 확신도 | {f['confidence']:.2f} |")
        src = {"both": "규칙 + LLM (교차 확인)", "llm": "LLM 판별기",
               "rule": "정적 규칙만"}[f["detected_by"]]
        L.append(f"| 탐지 경로 | {src} |")
        if f["rule_signals"]:
            L.append(f"| 규칙 신호 | {', '.join(f['rule_signals'])} |")
        L.append("")
        if f["evidence"]:
            ev = f["evidence"].replace("\n", " ").strip()
            mark = "✓ 원문 대조 확인" if f["evidence_verified"] else "⚠ 원문에서 확인 실패"
            L.append(f"**근거 (원문 인용, {mark})**\n")
            L.append(f"> {ev}\n")
        L.append(f"**판단 근거**: {f['reasoning']}\n")
        L.append(f"**권고 조치**: {f['action']}\n")

    # 이상 없는 도구
    L.append("## 3. 이상 없는 도구\n")
    if res["safe"]:
        L.append("| 도구 | 설명 |\n|---|---|")
        for s in res["safe"]:
            d = (s["description"] or "").replace("\n", " ").replace("|", "/")
            L.append(f"| `{s['tool_name']}` | {d[:90]} |")
    else:
        L.append("없음\n")
    L.append("")

    # 참고: 규칙만 반응한 항목 (위험 목록·종합판정에서 제외)
    L.append("## 4. 참고 — 정적 규칙만 반응한 항목\n")
    if res.get("notes"):
        L.append("아래 항목은 정적 규칙 엔진이 신호를 냈지만 **LLM 판별기는 정상으로 "
                 "판정**했습니다. 규칙은 문맥을 읽지 못해 오탐을 내므로 위험 목록과 "
                 "종합 판정에서 제외했으며, 투명성을 위해 기록만 남깁니다.\n")
        L.append("| 도구 | 규칙 | 신호 내용 |\n|---|---|---|")
        for n in res["notes"]:
            det = "; ".join(n["details"]).replace("|", "/")
            L.append(f"| `{n['tool_name']}` | {', '.join(n['rule_signals'])} | {det[:90]} |")
        L.append("")
    else:
        L.append("없음\n")

    # 데모일 때 정답 대조
    if demo:
        tp = sum(1 for f in res["findings"] if f.get("_truth"))
        fp = sum(1 for f in res["findings"] if f.get("_truth") is False)
        L.append("## 5. (데모 전용) 정답 대조\n")
        L.append(f"- 합성 악성 샘플을 정확히 탐지: **{tp}건**")
        L.append(f"- 정상 도구를 위험으로 오판: **{fp}건**\n")
        L.append("> 이 섹션은 데모 리포트에만 표시됩니다. 실제 감사에는 정답이 없습니다.\n")

    # 방법론과 한계
    L.append("## 6. 방법론 및 한계\n")
    L.append("**판별 방식**: 각 도구의 설명문(description)과 입력 스키마를 "
             "OWASP MCP Top 10 기준으로 LLM이 의미 수준에서 판별합니다. "
             "신뢰된 도구명 카탈로그를 함께 제공해 도구 섀도잉을 탐지하며, "
             "정적 규칙 엔진 결과를 교차 확인용으로 병행합니다.\n")
    L.append("**측정된 성능** (난이도 대응 홀드아웃 51건 기준)\n")
    L.append("| 지표 | 값 |\n|---|---|")
    L.append("| Precision | 0.950 |")
    L.append("| Recall | 0.905 |")
    L.append("| F1 | 0.927 |")
    L.append("| 오탐률(FPR) | 0.033 |\n")
    L.append("**한계**\n")
    L.append("- 권한 과다(scope_creep) 유형 중 구체적 권한을 명시하지 않고 "
             "모호하게 일반화한 표현은 탐지율이 낮습니다(4/6).")
    L.append("- 도구 정의만 검사합니다. 서버의 **실제 동작**은 검증하지 않으므로, "
             "정의는 정직하지만 구현이 악의적인 경우는 탐지 대상이 아닙니다.")
    L.append("- 이 리포트는 도입 판단의 보조 자료입니다. "
             "Critical/High 항목은 반드시 사람이 원문을 확인하십시오.\n")

    L.append("## 7. AI기본법 대응 참고\n")
    L.append("2026년 7월 21일 시행된 AI기본법 시행령은 고영향 AI 제공자에게 "
             "**안전성·신뢰성 확보 조치의 증명**을 요구합니다(1년 계도기간). "
             "본 리포트는 다음 항목의 증빙 자료로 활용할 수 있습니다.\n")
    L.append("| 확보 조치 | 본 리포트의 대응 |\n|---|---|")
    L.append("| 위험 식별 및 평가 | OWASP MCP Top 10 기준 도구별 위험 판정 |")
    L.append("| 조치 내역 기록 | 발견 항목별 권고 조치 및 심각도 |")
    L.append("| 이력 관리 | 감사 일시·모델·대상 도구 수 기록, JSON 원본 동시 저장 |\n")
    L.append("> 법적 효력에 대한 판단은 법률 전문가의 검토가 필요합니다. "
             "본 문서는 기술적 점검 결과이며 법률 자문이 아닙니다.\n")

    L.append("---\n")
    L.append("*Generated by MCP Security Auditor — "
             "https://github.com/tkdwns/mcp-security-auditor*")
    return "\n".join(L)


def main() -> None:
    ap = argparse.ArgumentParser(description="MCP 보안 감사 리포트 생성기")
    ap.add_argument("--server", default=None, help="수집본에서 감사할 서버 이름")
    ap.add_argument("--all", action="store_true", help="수집본의 모든 서버")
    ap.add_argument("--demo", choices=["clean", "poisoned", "mixed"],
                    help="포트폴리오용 데모 리포트")
    ap.add_argument("--model", default=None)
    ap.add_argument("--cap", type=int, default=80, help="호출 상한(안전장치)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    load_env(ROOT)
    model = args.model or os.environ.get("ANTHROPIC_MODEL", MODEL_DEFAULT)

    if args.demo:
        name, tools = tools_from_demo(args.demo)
    elif args.all:
        name, tools = tools_from_raw(None)
    elif args.server:
        name, tools = tools_from_raw(args.server)
    else:
        raise SystemExit("[!] --server / --all / --demo 중 하나를 지정하세요.")

    # 신뢰된 도구명 카탈로그 = 검증을 마친 수집본의 도구명
    catalog = set()
    if RAW.exists():
        raw = json.loads(RAW.read_text(encoding="utf-8"))
        for sv in raw.get("servers", []):
            for t in sv.get("tools", []):
                catalog.add(t["tool_name"])

    print("=" * 62)
    print(f"MCP 보안 감사 — {name}")
    print(f"  대상 도구 {len(tools)}개 / 모델 {model} / 카탈로그 {len(catalog)}개")
    if args.dry_run:
        print("  [DRY-RUN] 호출 없음")
        print("=" * 62)
        for t in tools:
            print(f"    - {t['tool_name']}")
        return
    print(f"  예상 비용 약 {len(tools) * 6.6:.0f}원")
    print("=" * 62)

    res = audit(tools, model, catalog, args.cap)

    OUTDIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(KST).strftime("%Y%m%d_%H%M")
    md = render_markdown(name, res, demo=bool(args.demo))
    md_path = OUTDIR / f"{name}_{stamp}.md"
    md_path.write_text(md, encoding="utf-8")

    json_path = OUTDIR / f"{name}_{stamp}.json"
    json_path.write_text(json.dumps({
        "server": name, "model": res["model"], "generated_at": stamp,
        "n_tools": res["n_tools"], "elapsed_sec": res["elapsed_sec"],
        "cost": res["cost"], "findings": res["findings"], "safe": res["safe"],
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    counts = Counter(f["severity"] for f in res["findings"])
    grade, _ = overall_grade(counts)
    print("\n" + "=" * 62)
    print(f"  종합 판정: {grade}")
    print(f"  발견 {len(res['findings'])}건 / 이상없음 {len(res['safe'])}건"
          + (f" / 규칙만 반응 {len(res['notes'])}건(참고)" if res.get("notes") else ""))
    print(f"  등급 분포: {dict(counts) or '없음'}")
    print(f"  소요 {res['elapsed_sec']}초 / 비용 {res['cost']['krw']}원")
    print("=" * 62)
    print(f"  리포트: {md_path}")
    print(f"  원본  : {json_path}")


if __name__ == "__main__":
    main()
