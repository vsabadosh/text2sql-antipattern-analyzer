from __future__ import annotations

import logging
import os
import time


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return logger


def now_ts() -> int:
    return int(time.time())


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def has_previous_failure(metadata: dict) -> bool:
    """Check if any previous analyzer in analysisSteps has failed."""
    analysis_steps = metadata.get("analysisSteps", [])
    return any(step.get("status") == "failed" for step in analysis_steps)
