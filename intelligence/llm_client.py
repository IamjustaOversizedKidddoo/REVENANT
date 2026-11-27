"""REVENANT — Single LLM client wrapper (Anthropic).

One thin, dependency-optional seam between REVENANT and a language model. Mirrors the
repo's "native fuzzer works without a binary" philosophy: this module imports cleanly
and never raises at import time even when the ``anthropic`` SDK is absent or no API key
is configured. Callers ask :meth:`LlmClient.available` first (or catch
:class:`LLMUnavailable`) and fall back to deterministic logic.

Environment:
    ANTHROPIC_API_KEY     API key. Absent -> client is unavailable (fallback path).
    REVENANT_LLM_MODEL    Model id. Default: a current, capable Claude model.
    REVENANT_LLM_MAX_TOKENS  Response cap (default 1024).
    REVENANT_LLM_TEMPERATURE Sampling temperature (default 0.2 — low, for analysis).
"""

from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger("revenant.llm")

# Sensible, user-overridable default. Kept as a plain string so importing this module
# never requires the SDK or network.
DEFAULT_MODEL = "claude-sonnet-4-5"
DEFAULT_MAX_TOKENS = 1024
DEFAULT_TEMPERATURE = 0.2


class LLMUnavailable(RuntimeError):
    """Raised by :meth:`LlmClient.complete` when no usable LLM backend is configured."""


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except (TypeError, ValueError):
        return default


class LlmClient:
    """Minimal wrapper around the Anthropic Messages API.

    Construction is always safe: it records config and lazily imports the SDK on first
    use. If the SDK is missing or no API key is set, :meth:`available` returns False and
    :meth:`complete` raises :class:`LLMUnavailable`.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get("ANTHROPIC_API_KEY")
        self.model = model or os.environ.get("REVENANT_LLM_MODEL") or DEFAULT_MODEL
        self.max_tokens = max_tokens if max_tokens is not None else _env_int("REVENANT_LLM_MAX_TOKENS", DEFAULT_MAX_TOKENS)
        self.temperature = (
            temperature if temperature is not None else _env_float("REVENANT_LLM_TEMPERATURE", DEFAULT_TEMPERATURE)
        )
        self._client = None  # lazily constructed SDK client

    # -- capability probing ------------------------------------------------

    @staticmethod
    def sdk_installed() -> bool:
        """True if the optional ``anthropic`` package can be imported."""
        import importlib.util

        return importlib.util.find_spec("anthropic") is not None

    def available(self) -> bool:
        """True only if both the SDK is installed and an API key is present."""
        return bool(self.api_key) and self.sdk_installed()

    # -- completion --------------------------------------------------------

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        if not self.api_key:
            raise LLMUnavailable("ANTHROPIC_API_KEY is not set; using deterministic fallback.")
        try:
            import anthropic  # type: ignore
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise LLMUnavailable(
                "The 'anthropic' package is not installed. Install with: pip install -e .[llm]"
            ) from exc
        self._client = anthropic.Anthropic(api_key=self.api_key)
        return self._client

    def complete(self, system: str, user: str) -> str:
        """Return the model's text completion for a system+user prompt.

        Raises :class:`LLMUnavailable` if no backend is configured or the call fails,
        so every caller can wrap this in try/except and degrade gracefully.
        """
        client = self._ensure_client()
        try:
            msg = client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except LLMUnavailable:
            raise
        except Exception as exc:  # network / auth / rate-limit — treat as unavailable
            logger.warning("LLM call failed (%s); falling back to deterministic path.", exc)
            raise LLMUnavailable(str(exc)) from exc

        # Concatenate text blocks from the response content.
        parts = []
        for block in getattr(msg, "content", []) or []:
            text = getattr(block, "text", None)
            if text:
                parts.append(text)
        out = "".join(parts).strip()
        if not out:
            raise LLMUnavailable("LLM returned an empty response.")
        return out


def get_default_client() -> LlmClient:
    """Convenience constructor reading all configuration from the environment."""
    return LlmClient()
