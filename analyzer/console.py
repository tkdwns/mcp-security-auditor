from __future__ import annotations
import sys
def enable_utf8_console() -> None:
    for st in (sys.stdout, sys.stderr):
        r=getattr(st,"reconfigure",None)
        if r:
            try: r(encoding="utf-8", errors="replace")
            except (ValueError, OSError): pass
enable_utf8_console()
