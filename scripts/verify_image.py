"""Docker 없이 '이미지에 들어갈 파일만으로 앱이 뜨는지' 검증한다.

왜 필요한가
-----------
Docker 배포에서 가장 흔한 실패는 문법 오류가 아니라 **파일 누락**이다.
로컬에서는 프로젝트 전체가 있으니 잘 돌지만, 컨테이너에는 Dockerfile 이
COPY 한 것만 들어간다. 빠진 모듈이나 데이터 파일이 있으면 배포 후에야 터진다.

이 스크립트는 Dockerfile 의 COPY 목록과 동일한 파일만 임시 폴더에 모아,
그 안에서 앱을 기동해 본다. Docker Desktop 이 없어도 실행할 수 있다.

사용법:
    python scripts/verify_image.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Dockerfile 의 COPY 구문과 1:1 로 맞춘다. Dockerfile 을 바꾸면 여기도 바꿀 것.
COPY_DIRS = ["api", "analyzer", "data/catalog", "reports"]
COPY_FILES = [
    "requirements-api.txt",
    "experiments/__init__.py", "experiments/strategies.py",
    "report/__init__.py", "report/severity.py",
]

BOOT = r'''
import sys, os
sys.path.insert(0, os.getcwd())
os.environ.setdefault("ANTHROPIC_API_KEY", "sk-verify-dummy")
from fastapi.testclient import TestClient
from api.main import app
c = TestClient(app)

checks = []
h = c.get("/health")
checks.append(("GET /health", h.status_code == 200))
j = h.json()
checks.append(("신뢰 카탈로그 로드", j.get("catalog_size", 0) > 0))
checks.append(("데모 리포트 존재", len(j.get("demos", [])) > 0))
checks.append(("GET / (웹 UI)", c.get("/").status_code == 200 and len(c.get("/").text) > 3000))
checks.append(("GET /docs", c.get("/docs").status_code == 200))
for k in j.get("demos", []):
    checks.append((f"GET /demo/{k}", c.get(f"/demo/{k}").status_code == 200))

try:
    from api.service import load_catalog, run_audit
    from experiments.strategies import make_catalog_strategy
    from report.severity import assess
    from analyzer.rules import evaluate_sample
    s = make_catalog_strategy(load_catalog())
    checks.append(("판별 파이프라인 import", len(s.system_text) > 1000))
except Exception as e:
    checks.append((f"판별 파이프라인 import - {type(e).__name__}: {e}", False))

ok = True
for name, passed in checks:
    print("  [%s] %s" % ("OK  " if passed else "FAIL", name))
    ok = ok and passed
print("__RESULT__", "PASS" if ok else "FAIL")
'''


def main() -> None:
    missing = [p for p in COPY_DIRS + COPY_FILES if not (ROOT / p).exists()]
    if missing:
        print("[!] Dockerfile 이 COPY 하는 대상이 없습니다:")
        for m in missing:
            print(f"    - {m}")
        sys.exit(1)

    with tempfile.TemporaryDirectory(prefix="mcp-img-") as tmp:
        stage = Path(tmp)
        for d in COPY_DIRS:
            shutil.copytree(ROOT / d, stage / d,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for f in COPY_FILES:
            dst = stage / f
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / f, dst)

        files = [p for p in stage.rglob("*") if p.is_file()]
        size_kb = sum(p.stat().st_size for p in files) / 1024

        print("=" * 62)
        print("이미지 구성 검증 (Docker 불필요)")
        print("=" * 62)
        print(f"  파일 {len(files)}개 / 약 {size_kb:.0f} KB")
        print("-" * 62)

        (stage / "_boot.py").write_text(BOOT, encoding="utf-8")
        r = subprocess.run([sys.executable, "_boot.py"], cwd=stage,
                           capture_output=True, text=True, encoding="utf-8")
        out = (r.stdout or "") + (r.stderr or "")
        for line in out.splitlines():
            if not line.startswith("__RESULT__"):
                print(line)

        print("=" * 62)
        if "__RESULT__ PASS" in out:
            print("  통과 — 이 파일 구성으로 배포하면 앱이 기동됩니다.")
        else:
            print("  실패 — 위 FAIL 항목을 확인하세요.")
            print("  (Dockerfile 의 COPY 목록에 빠진 것이 없는지 먼저 보세요)")
            sys.exit(1)


if __name__ == "__main__":
    main()
