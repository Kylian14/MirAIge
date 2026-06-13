"""Shared structured logging setup (JSON to stdout)."""
import logging
import os
import sys
from typing import Final

_FORMAT: Final = '{"ts":"%(asctime)s","level":"%(levelname)s","svc":"%(name)s","msg":%(message)s}'


def setup(service_name: str) -> logging.Logger:
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(_FORMAT, datefmt="%Y-%m-%dT%H:%M:%S"))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    return logging.getLogger(service_name)
