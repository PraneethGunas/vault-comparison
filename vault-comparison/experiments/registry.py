"""Experiment registry.

Each experiment registers itself here. The CLI runner discovers experiments
through this module.
"""

from typing import Callable, Dict, List, Optional
from dataclasses import dataclass

from adapters.base import VaultAdapter
from harness.metrics import ExperimentResult


@dataclass
class ExperimentSpec:
    """Metadata for a registered experiment."""
    name: str
    description: str
    run_fn: Callable[[VaultAdapter], ExperimentResult]
    required_covenants: Optional[List[str]] = None  # None = all, ["ccv"] = ccv-only
    tags: List[str] = None

    def supports(self, adapter: VaultAdapter) -> bool:
        if self.required_covenants is None:
            return True
        return adapter.name in self.required_covenants


# Global registry
EXPERIMENTS: Dict[str, ExperimentSpec] = {}


def register(name: str, description: str, required_covenants: Optional[List[str]] = None, tags: List[str] = None):
    """Decorator to register an experiment function."""
    def decorator(fn):
        EXPERIMENTS[name] = ExperimentSpec(
            name=name,
            description=description,
            run_fn=fn,
            required_covenants=required_covenants,
            tags=tags or [],
        )
        return fn
    return decorator


def get_experiment(name: str) -> ExperimentSpec:
    if name not in EXPERIMENTS:
        available = ", ".join(sorted(EXPERIMENTS.keys()))
        raise KeyError(f"Unknown experiment '{name}'. Available: {available}")
    return EXPERIMENTS[name]
