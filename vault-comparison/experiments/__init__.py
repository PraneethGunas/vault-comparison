"""Comparative experiments for covenant vault designs.

Each experiment module defines a function that takes an adapter and returns
an ExperimentResult. The CLI runner calls each experiment against each
adapter and produces comparison reports.
"""

from experiments.registry import EXPERIMENTS, get_experiment

__all__ = ["EXPERIMENTS", "get_experiment"]
