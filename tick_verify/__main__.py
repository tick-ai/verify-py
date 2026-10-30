"""python -m tick_verify <file>: check one document, and say what the check does not establish.

It reads the one file and makes no network call. Exit 0 when the document is
valid, 1 when it is not, 2 when there is no file or it cannot be read, as
spec/SPEC.md's "Using it" says of tick-verify.
"""

from __future__ import annotations

import sys
from typing import Callable, Sequence

from . import verify_document

USAGE = "usage: python -m tick_verify <file>"


def run(argv: Sequence[str], out: Callable[[str], None], err: Callable[[str], None]) -> int:
    if list(argv) == ["--help"]:
        out(USAGE)
        return 0
    if len(argv) != 1:
        err(USAGE)
        return 2
    path = argv[0]
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as error:
        err(f"tick_verify: cannot read {path}: {error}")
        return 2
    verdict = verify_document(text)
    out(f"{path}: {verdict.kind}: {'valid' if verdict.valid else 'NOT valid'}")
    for reason in verdict.reasons:
        out(f"  {reason}")
    if verdict.limits:
        out("What this does not establish:")
        for line in verdict.limits:
            out(f"  - {line}")
    return 0 if verdict.valid else 1


def main() -> None:
    sys.exit(run(sys.argv[1:], print, lambda line: print(line, file=sys.stderr)))


if __name__ == "__main__":
    main()
