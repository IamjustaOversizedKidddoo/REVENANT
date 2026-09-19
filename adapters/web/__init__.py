"""REVENANT Web Tool Adapters"""
from .ffuf_adapter import FfufAdapter
from .nuclei_adapter import NucleiAdapter
from .katana_adapter import KatanaAdapter
from .dast_adapter import DastAdapter

__all__ = ["NucleiAdapter", "FfufAdapter", "KatanaAdapter", "DastAdapter"]
