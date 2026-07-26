"""Substratum — one normalized byte view over the game-preservation
container zoo. Contract: DESIGN.md (frozen) + substratum.contract.
Registry/backlog: NORMALIZERS.md. Downstream consumers (Stratum, Quarry,
Kura, Interlinear) import contract types and manifests only.
"""

from substratum.normalize import normalize

__all__ = ["normalize", "__version__"]

__version__ = "0.0.8"
