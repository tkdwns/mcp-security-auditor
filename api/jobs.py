"""인메모리 작업 저장소.

왜 Redis / Celery 를 쓰지 않는가
--------------------------------
이 서비스는 단일 인스턴스, 동시 사용자 소수, 작업 수명 1분 내외다.
그 규모에 브로커와 워커를 붙이면 배포 실패 지점만 늘어난다.
표준 라이브러리 dict + Lock 으로 충분하다.

**한계는 명시한다**: 프로세스가 재시작되면 진행 중이던 작업은 사라진다.
여러 인스턴스로 확장하면 인스턴스 간 작업 조회가 불가능하다.
그때가 오면 Redis 로 교체하면 되고, 인터페이스(JobStore)는 그대로 둔 채
구현만 바꿀 수 있도록 분리해 두었다.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

KST = timezone(timedelta(hours=9))

# 오래된 작업을 정리하는 기준 (메모리 누수 방지)
JOB_TTL_MINUTES = 30
MAX_JOBS_RETAINED = 200


@dataclass
class Job:
    job_id: str
    status: str = "queued"          # queued | running | done | error
    progress: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(KST))
    result: dict[str, Any] | None = None
    error: str | None = None
    notice: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "progress": self.progress,
            "created_at": self.created_at.isoformat(timespec="seconds"),
            "result": self.result,
            "error": self.error,
            "notice": self.notice,
        }


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def create(self) -> Job:
        job = Job(job_id=uuid.uuid4().hex[:12])
        with self._lock:
            self._evict_locked()
            self._jobs[job.job_id] = job
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def update(self, job_id: str, **fields: Any) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            for k, v in fields.items():
                setattr(job, k, v)

    def running_count(self) -> int:
        with self._lock:
            return sum(1 for j in self._jobs.values()
                       if j.status in ("queued", "running"))

    def _evict_locked(self) -> None:
        """TTL 초과분과 초과 보관분을 제거한다. 호출자가 락을 쥔 상태여야 한다."""
        now = datetime.now(KST)
        cutoff = now - timedelta(minutes=JOB_TTL_MINUTES)
        stale = [k for k, j in self._jobs.items()
                 if j.created_at < cutoff and j.status in ("done", "error")]
        for k in stale:
            self._jobs.pop(k, None)

        if len(self._jobs) > MAX_JOBS_RETAINED:
            finished = sorted(
                (j for j in self._jobs.values() if j.status in ("done", "error")),
                key=lambda j: j.created_at)
            for j in finished[: len(self._jobs) - MAX_JOBS_RETAINED]:
                self._jobs.pop(j.job_id, None)


store = JobStore()
