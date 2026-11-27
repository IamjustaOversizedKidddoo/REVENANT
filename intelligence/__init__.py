"""REVENANT — Intelligence layer (attack-graph correlation + LLM reasoning).

Optional, graceful-degrading reasoning utilities:

- ``llm_client``: a single thin Anthropic wrapper that is safe to import even when
  the ``anthropic`` SDK is not installed and no API key is present.
- ``analyst``: post-campaign Analyst / Narrator that enriches a finding set into an
  intelligence brief (LLM path, with a deterministic template fallback).

Nothing here is required by the core CLI; the platform runs fully without an API key.
"""
