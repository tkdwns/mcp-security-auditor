"""Windows 콘솔 출력 인코딩 보정.

Windows 한국어 환경의 기본 콘솔 코드페이지는 cp949 다.
파이썬이 stdout 을 cp949 로 열면 '→', '✓' 같은 기호에서
UnicodeEncodeError 가 나면서 프로그램이 죽는다.

이 모듈을 import 하는 것만으로 stdout/stderr 을 UTF-8 로 바꾼다.
(Python 3.7+ 의 TextIOWrapper.reconfigure 사용)
"""

from __future__ import annotations

import sys


def enable_utf8_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                # 리다이렉트된 스트림 등 재설정 불가한 경우는 조용히 넘어간다
                pass


enable_utf8_console()
