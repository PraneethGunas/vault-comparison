"""Structured logging for the vault-comparison framework.

Dual-output: structured JSON to file (for machine parsing), pretty-printed
to console (for human reading).  Every log entry carries covenant, experiment,
and phase as bound context.

Usage:
    from harness.logging import setup_logging, get_logger

    setup_logging(log_dir=Path("results/run-001"))
    log = get_logger(experiment="fee_pinning", covenant="ctv")
    log.info("vault_created", txid=vault.vault_txid, amount=vault.amount_sats)
    log.warning("pinning_detected", depth=depth, desc_count=desc_count)

If structlog is not installed, falls back to stdlib logging with a simple
formatter.  This allows the framework to run without structlog as a hard
dependency.
"""

import logging
import sys
from pathlib import Path
from typing import Optional

try:
    import structlog
    HAS_STRUCTLOG = True
except ImportError:
    HAS_STRUCTLOG = False


def setup_logging(log_dir: Optional[Path] = None, level: str = "INFO"):
    """Configure logging for the framework.

    Args:
        log_dir: If provided, write structured JSON logs to log_dir/experiment.jsonl.
        level: Minimum log level (DEBUG, INFO, WARNING, ERROR).
    """
    if HAS_STRUCTLOG:
        _setup_structlog(log_dir, level)
    else:
        _setup_stdlib(log_dir, level)


def get_logger(**initial_context):
    """Get a logger with bound context fields.

    Args:
        **initial_context: Fields to bind to every log entry (e.g.,
            experiment="fee_pinning", covenant="ctv").
    """
    if HAS_STRUCTLOG:
        return structlog.get_logger(**initial_context)
    else:
        logger = logging.getLogger("vault_comparison")
        # Simulate bound context via LoggerAdapter
        return logging.LoggerAdapter(logger, initial_context)


# ── structlog setup ──────────────────────────────────────────────────


def _setup_structlog(log_dir: Optional[Path], level: str):
    """Configure structlog with console + optional JSON file output."""
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    # File handler for JSON logs
    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_dir / "experiment.jsonl")
        file_handler.setFormatter(logging.Formatter("%(message)s"))

        # Create a stdlib logger that structlog can write JSON to
        json_logger = logging.getLogger("vault_comparison.json")
        json_logger.addHandler(file_handler)
        json_logger.setLevel(logging.getLevelName(level))

    structlog.configure(
        processors=processors + [structlog.dev.ConsoleRenderer()],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(level)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


# ── stdlib fallback ──────────────────────────────────────────────────


def _setup_stdlib(log_dir: Optional[Path], level: str):
    """Fallback to stdlib logging if structlog is not installed."""
    logger = logging.getLogger("vault_comparison")
    logger.setLevel(logging.getLevelName(level))

    # Console handler
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
    ))
    logger.addHandler(console)

    # File handler
    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_dir / "experiment.log")
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s"
        ))
        logger.addHandler(file_handler)
