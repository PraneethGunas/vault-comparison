"""Upstream module loading with sys.path isolation.

Each upstream repo (simple-ctv-vault, pymatt, simple-cat-csfs-vault, simple-op-vault)
has its own module namespace (main.py, rpc.py, vault.py, etc.). Loading one
clobbers the other in sys.modules. This module provides safe loading.
"""
import sys
from pathlib import Path
from typing import List, Dict, Any


class UpstreamModuleLoader:
    """Load modules from an upstream repo without polluting sys.path permanently.

    Usage:
        loader = UpstreamModuleLoader(
            repo_path=CFG.ctv_repo,
            evict_modules=["main", "rpc", "vault"],
        )
        modules = loader.load(["vault", "rpc", "main"])
        ctv_vault = modules["vault"]
    """

    def __init__(self, repo_path: Path, evict_modules: List[str]):
        self.repo_path = repo_path.resolve()
        self.evict_modules = evict_modules

    def load(self, module_names: List[str]) -> Dict[str, Any]:
        """Load the specified modules from the upstream repo.

        Evicts conflicting cached modules, inserts the repo path at the
        front of sys.path, imports, then returns the modules.
        """
        repo_str = str(self.repo_path)

        # Clean sys.path
        if repo_str in sys.path:
            sys.path.remove(repo_str)
        sys.path.insert(0, repo_str)

        # Evict conflicting modules from other repos
        for mod_name in self.evict_modules:
            if mod_name in sys.modules:
                cached = sys.modules[mod_name]
                cached_path = getattr(cached, "__file__", "") or ""
                if repo_str not in cached_path:
                    del sys.modules[mod_name]

        # Import
        result = {}
        for name in module_names:
            result[name] = __import__(name)

        return result
