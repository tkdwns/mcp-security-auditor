"""MCP Security Auditor — FastAPI 애플리케이션.

실행:
    uvicorn api.main:app --reload
    → http://localhost:8000/docs  (자동 생성 API 문서)

설계 요약
---------
- MCP 서버에 접속하지 않고 **도구 정의(JSON)를 입력받는다.**
  컨테이너에서 임의의 서버 프로세스를 실행하는 것 자체가 공격면이기 때문이다.
- 감사는 도구 14개에 약 50초 걸린다. 대부분의 PaaS 가 요청을 30~60초에 끊으므로
  **비동기 작업 + 폴링** 구조를 쓴다.
- /demo 는 LLM 을 호출하지 않는다. API 키 없이도 결과를 보여주기 위한 경로이며,
  예산 소진 시 폴백 경로로도 쓰인다.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

# 프로젝트 루트를 import 경로에 추가 (uvicorn 을 어디서 실행하든 동작하도록)
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from . import demo as demo_mod  # noqa: E402
from .guard import (  # noqa: E402
    DAILY_TOOL_BUDGET, MAX_BODY_BYTES, MAX_CONCURRENT_JOBS,
    RATE_LIMIT_PER_HOUR, budget, client_key, rate_limiter,
)
from .jobs import store  # noqa: E402
from .models import (  # noqa: E402
    MAX_TOOLS_PER_REQUEST, AuditRequest, HealthResponse, JobCreated, JobStatus,
)
from .service import llm_available, load_catalog, run_audit, to_internal  # noqa: E402

app = FastAPI(
    title="MCP Security Auditor",
    version="0.4.0",
    description=(
        "MCP 서버의 도구 정의에 숨겨진 악의적 지시를 LLM으로 탐지합니다.\n\n"
        "난이도 대응 홀드아웃 51건 기준 **F1 0.927 / 재현율 0.905 / 오탐률 0.033**.\n\n"
        "API 키 없이 결과를 보시려면 `/demo/{kind}` 를 호출하세요 (무료)."
    ),
)

CATALOG = load_catalog()


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    """요청 본문 크기 제한.

    Content-Length 만 보고 조기 거부한다. 헤더가 없는(chunked) 요청은
    통과시키되, 스키마 단계의 도구 수·문자열 길이 제한이 다음 방어선이 된다.
    """
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
        return JSONResponse(
            status_code=413,
            content={"detail": f"요청이 너무 큽니다. 최대 {MAX_BODY_BYTES // 1024}KB."},
        )
    return await call_next(request)


@app.get("/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    """헬스체크. 배포 플랫폼이 주기적으로 호출한다."""
    return HealthResponse(
        status="ok",
        version=app.version,
        llm_available=llm_available(),
        catalog_size=len(CATALOG),
        demos=demo_mod.available(),
        budget=budget.snapshot(),
        limits={
            "rate_limit_per_hour": RATE_LIMIT_PER_HOUR,
            "daily_tool_budget": DAILY_TOOL_BUDGET,
            "max_concurrent_jobs": MAX_CONCURRENT_JOBS,
            "max_body_kb": MAX_BODY_BYTES // 1024,
        },
    )


@app.get("/demo/{kind}", tags=["demo"])
def get_demo(kind: str):
    """미리 생성해 둔 감사 결과. **LLM 호출 없음 → 비용 0원.**

    kind: clean | poisoned | mixed
    """
    d = demo_mod.load(kind)
    if d is None:
        raise HTTPException(
            404, f"'{kind}' 데모가 없습니다. 사용 가능: {demo_mod.available()}")
    return d


@app.get("/demo/{kind}/report.md", response_class=PlainTextResponse, tags=["demo"])
def get_demo_markdown(kind: str) -> str:
    md = demo_mod.load_markdown(kind)
    if md is None:
        raise HTTPException(404, f"'{kind}' 데모 리포트가 없습니다.")
    return md


def _run_job(job_id: str, server_name: str, tools: list[dict],
             catalog: set[str], budgeted: int = 0) -> None:
    """백그라운드 실행 본체.

    동기 함수로 두면 FastAPI 가 스레드풀에서 실행하므로 이벤트 루프를 막지 않는다.
    """
    store.update(job_id, status="running", progress=f"0/{len(tools)}")

    def on_progress(i: int, total: int, name: str) -> None:
        store.update(job_id, progress=f"{i}/{total} ({name})")

    try:
        result = run_audit(server_name, tools, catalog, on_progress=on_progress)
        store.update(job_id, status="done", result=result,
                     progress=f"{len(tools)}/{len(tools)}")
    except Exception as exc:  # noqa: BLE001
        # 실행이 실패했으면 소비한 예산을 되돌린다.
        # (모델 오류로 판별이 안 됐는데 예산만 깎이면 억울하다)
        if budgeted:
            budget.refund(budgeted)
        store.update(job_id, status="error", error=f"{type(exc).__name__}: {exc}")


def _fallback_job(reason: str) -> JobCreated | None:
    """예산 소진 시: 에러 대신 캐시된 데모 결과를 담은 완료 작업을 만든다.

    클라이언트는 평소와 동일하게 폴링하면 되고, 결과의 verdict 앞에 안내 문구가
    붙는다. 500 에러는 '고장'으로 보이지만 이쪽은 '설계'로 보인다.
    """
    result = demo_mod.as_audit_result("poisoned", notice=reason)
    if result is None:
        return None
    job = store.create()
    store.update(job.job_id, status="done", progress="demo", result=result,
                 notice=reason)
    return JobCreated(job_id=job.job_id, status="queued",
                      poll_url=f"/audit/{job.job_id}")


@app.post("/audit", response_model=JobCreated, status_code=202, tags=["audit"])
def start_audit(req: AuditRequest, request: Request,
                background: BackgroundTasks) -> JobCreated:
    """감사를 시작하고 즉시 job_id 를 반환한다.

    결과는 `GET /audit/{job_id}` 로 폴링하세요. 도구 14개 기준 약 50초.

    **제한**: IP당 시간당 요청 수, 하루 총 판별 도구 수에 상한이 있습니다.
    예산이 소진되면 실제 판별 대신 데모 결과가 반환됩니다(안내 문구 포함).
    """
    if not llm_available():
        raise HTTPException(
            503,
            "판별에 필요한 ANTHROPIC_API_KEY 가 설정되지 않았습니다. "
            "비용 없이 결과를 보시려면 /demo/poisoned 를 이용하세요.",
        )
    if len(req.tools) > MAX_TOOLS_PER_REQUEST:
        raise HTTPException(400, f"한 번에 최대 {MAX_TOOLS_PER_REQUEST}개까지 검사합니다.")

    # --- 방어 3: IP당 요청 빈도 ---
    key = client_key(request)
    allowed, remaining = rate_limiter.check(key)
    if not allowed:
        raise HTTPException(
            429,
            f"요청이 너무 잦습니다. 시간당 {RATE_LIMIT_PER_HOUR}회까지 가능합니다. "
            f"{rate_limiter.retry_after(key)}초 후 다시 시도하거나, "
            f"비용 없이 결과를 보시려면 /demo/poisoned 를 이용하세요.",
            headers={"Retry-After": str(rate_limiter.retry_after(key))},
        )

    # --- 방어: 동시 실행 수 (0.1 vCPU 환경 보호) ---
    if store.running_count() >= MAX_CONCURRENT_JOBS:
        raise HTTPException(
            503, "현재 처리 중인 작업이 많습니다. 잠시 후 다시 시도해 주세요.",
            headers={"Retry-After": "30"})

    # --- 방어 4: 일일 예산. 소진 시 에러 대신 데모로 폴백 ---
    n = len(req.tools)
    if not budget.try_consume(n):
        fb = _fallback_job(
            "[안내] 오늘의 무료 판별 예산이 모두 소진되어 미리 생성해 둔 데모 결과를 "
            "보여드립니다. 실제 판별은 내일 다시 이용하실 수 있습니다.")
        if fb is not None:
            return fb
        raise HTTPException(
            429, f"오늘의 판별 예산({DAILY_TOOL_BUDGET}개)이 모두 소진되었습니다.")

    catalog = set(req.catalog) if req.catalog else CATALOG
    tools = to_internal(req.server_name, req.tools)

    job = store.create()
    background.add_task(_run_job, job.job_id, req.server_name, tools, catalog, n)
    return JobCreated(job_id=job.job_id, status="queued",
                      poll_url=f"/audit/{job.job_id}")


@app.get("/audit/{job_id}", response_model=JobStatus, tags=["audit"])
def get_audit(job_id: str) -> JobStatus:
    """작업 상태·결과 조회."""
    job = store.get(job_id)
    if job is None:
        raise HTTPException(
            404, "해당 작업을 찾을 수 없습니다. 만료되었거나(30분) 서버가 재시작되었습니다.")
    return JobStatus(**job.to_dict())


STATIC_DIR = Path(__file__).resolve().parent / "static"


@app.get("/", include_in_schema=False)
def index():
    """웹 UI (단일 HTML 페이지).

    프레임워크를 쓰지 않는다. 화면 하나에 빌드 단계를 도입하면 Docker 이미지가
    복잡해지고 배포 실패 지점이 늘어난다. 순수 HTML+CSS+JS 면 충분하다.
    """
    f = STATIC_DIR / "index.html"
    if not f.exists():
        return JSONResponse({"name": "MCP Security Auditor", "docs": "/docs",
                             "demo": [f"/demo/{k}" for k in demo_mod.available()]})
    return FileResponse(f, media_type="text/html")
