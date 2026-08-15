"""남용·비용 방어.

왜 필요한가
-----------
공개 URL 뒤에 **내 API 키가 물려 있다.** 누군가 스크립트로 반복 호출하면
비용이 그대로 청구된다. 실제로 흔히 일어나는 사고이며, 개인 프로젝트가
공개 데모를 포기하는 가장 큰 이유이기도 하다.

방어는 네 겹으로 둔다.
  1) 요청당 도구 수 상한   — 스키마 단계(models.py)에서 차단
  2) 요청 본문 크기 상한   — 미들웨어에서 차단
  3) IP당 요청 빈도 제한   — 슬라이딩 윈도우
  4) 일일 총 도구 수 예산  — 소진 시 **데모 결과로 폴백**

4번이 핵심이다. 예산이 떨어졌을 때 500 에러를 내면 '고장난 프로젝트'로 보이지만,
캐시된 데모 결과로 우아하게 폴백하면 '의도된 설계'로 보인다. 채용 담당자가
링크를 눌렀을 때 무엇을 보게 되는지가 이 프로젝트의 첫인상이다.

모든 값은 환경변수로 조정 가능하다. 배포 후 코드 수정 없이 조일 수 있어야 한다.
"""

from __future__ import annotations

import os
import threading
from collections import deque
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


# --- 정책 (환경변수로 조정) ---
RATE_LIMIT_PER_HOUR = _env_int("RATE_LIMIT_PER_HOUR", 3)      # IP당 시간당 요청
DAILY_TOOL_BUDGET = _env_int("DAILY_TOOL_BUDGET", 200)        # 하루 총 판별 도구 수
MAX_CONCURRENT_JOBS = _env_int("MAX_CONCURRENT_JOBS", 2)      # 동시 실행 작업 수
MAX_BODY_BYTES = _env_int("MAX_BODY_BYTES", 256 * 1024)       # 요청 본문 256KB


class RateLimiter:
    """IP별 슬라이딩 윈도우 제한.

    Redis 없이 메모리 deque 로 구현한다. 단일 인스턴스이므로 충분하다.
    인스턴스를 늘리면 IP별 카운트가 분산되어 정확도가 떨어지는데,
    그때는 예산 상한(4번 방어)이 마지막 방어선으로 남는다.
    """

    def __init__(self, limit: int, window_sec: int = 3600) -> None:
        self.limit = limit
        self.window = window_sec
        self._hits: dict[str, deque[datetime]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int]:
        """(허용 여부, 남은 횟수)."""
        now = datetime.now(KST)
        cutoff = now - timedelta(seconds=self.window)
        with self._lock:
            dq = self._hits.setdefault(key, deque())
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.limit:
                return False, 0
            dq.append(now)
            # 오래된 IP 항목 정리 (메모리 누수 방지)
            if len(self._hits) > 5000:
                for k in [k for k, v in self._hits.items() if not v][:1000]:
                    self._hits.pop(k, None)
            return True, self.limit - len(dq)

    def retry_after(self, key: str) -> int:
        with self._lock:
            dq = self._hits.get(key)
            if not dq:
                return 0
            elapsed = (datetime.now(KST) - dq[0]).total_seconds()
            return max(1, int(self.window - elapsed))


class DailyBudget:
    """하루 단위 판별 도구 수 예산. KST 자정에 초기화된다."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._day = datetime.now(KST).date()
        self._used = 0
        self._lock = threading.Lock()

    def _roll_locked(self) -> None:
        today = datetime.now(KST).date()
        if today != self._day:
            self._day = today
            self._used = 0

    def try_consume(self, n: int) -> bool:
        with self._lock:
            self._roll_locked()
            if self._used + n > self.limit:
                return False
            self._used += n
            return True

    def refund(self, n: int) -> None:
        """작업이 시작조차 못 했을 때 되돌린다."""
        with self._lock:
            self._used = max(0, self._used - n)

    def snapshot(self) -> dict[str, int | str]:
        with self._lock:
            self._roll_locked()
            return {"date": str(self._day), "used": self._used,
                    "limit": self.limit, "remaining": max(0, self.limit - self._used)}


rate_limiter = RateLimiter(RATE_LIMIT_PER_HOUR)
budget = DailyBudget(DAILY_TOOL_BUDGET)


def client_key(request) -> str:
    """클라이언트 식별자.

    Render 등 PaaS 는 리버스 프록시 뒤에 있으므로 request.client.host 는
    프록시 IP 가 된다. X-Forwarded-For 의 첫 항목이 실제 클라이언트다.
    (헤더는 위조 가능하므로 이것만으로는 완전한 방어가 아니다.
     그래서 일일 예산 상한을 별도로 둔다.)
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
