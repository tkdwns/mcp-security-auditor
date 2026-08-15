# ──────────────────────────────────────────────────────────────
# MCP Security Auditor — 배포용 이미지
#
# 설계 판단
#  · Node.js 를 넣지 않는다. API 는 MCP 서버에 접속하지 않고 도구 정의(JSON)를
#    입력받기 때문이다(컨테이너에서 임의의 서버 프로세스를 띄우는 것 자체가
#    공격면이고, 우리가 탐지하려는 대상이 바로 악성 서버다).
#  · 런타임 의존성만 설치한다(requirements-api.txt). pandas·scikit-learn·
#    matplotlib 은 실험/시각화 전용이라 판별에 필요 없고, Render 무료 플랜은
#    RAM 512MB 라 이미지를 가볍게 유지해야 한다.
#  · 의존성 레이어를 소스보다 먼저 만든다. 코드만 바뀌면 pip 단계가 캐시된다.
#  · API 키는 이미지에 넣지 않는다. 런타임 환경변수로 주입한다.
# ──────────────────────────────────────────────────────────────
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# 1) 의존성 (변경 빈도가 낮으므로 먼저)
COPY requirements-api.txt .
RUN pip install --no-cache-dir -r requirements-api.txt

# 2) 애플리케이션 코드 — 런타임에 실제로 import 되는 것만 복사
#    (collector·benchmark·viz·docs·실험 결과 데이터는 이미지에 넣지 않는다)
COPY api/       ./api/
COPY analyzer/  ./analyzer/
COPY experiments/__init__.py experiments/strategies.py ./experiments/
COPY report/__init__.py report/severity.py ./report/

# 3) 런타임 데이터
#    · data/catalog : 신뢰된 도구명 카탈로그(섀도잉 탐지의 대조 기준).
#      data/raw 는 .gitignore 대상이라 이 파일만 따로 커밋해 둔다.
#    · reports      : /demo 엔드포인트가 서빙하는 미리 생성된 감사 결과
COPY data/catalog/ ./data/catalog/
COPY reports/      ./reports/

# 4) 비루트 사용자로 실행
RUN useradd --create-home --uid 10001 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Render 는 $PORT 를 주입한다. 로컬에서는 8000 을 쓴다.
# 워커 1개: 무료 플랜은 0.1 vCPU 라 늘려도 이득이 없고, 작업 상태를 인메모리로
# 관리하므로 워커가 여러 개면 job 조회가 워커 간에 어긋난다.
CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
