"""Entry point.

`python -m scanner` starts the HTTP service (the container default).
`python -m scanner scan PATH` runs the CLI, which is what the smoke suite uses.
"""

from __future__ import annotations

import sys

from .api import serve
from .cli import main


def run() -> int:
    argv = sys.argv[1:]
    if argv:
        return main(argv)
    return serve()


if __name__ == "__main__":
    raise SystemExit(run())
