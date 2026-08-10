"""Perimetry reconnaissance modules.

Every module here is executed as a standalone subprocess by perimetry.core.runner
and prints rich-formatted output to stdout. On Windows the default console
encoding (cp1252) cannot represent the status glyphs most modules use, so a
single failed lookup could raise UnicodeEncodeError and kill the run. Force
UTF-8 on import so every module inherits it, whether it is launched by the
runner or invoked directly with `python -m perimetry.modules.<name>`.
"""

import sys

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
