import os
import re
import time
from types import SimpleNamespace

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_groq import ChatGroq

from config import MODEL_NAME, TEMPERATURE

GOOGLE_MODEL_NAME = os.getenv("GOOGLE_MODEL_NAME", "gemini-flash-latest")

_RETRY_PATTERNS = (
    re.compile(r"retry in ([\d.]+)s", re.IGNORECASE),
    re.compile(r"'retryDelay':\s*'(\d+(?:\.\d+)?)s'"),
)


def _extract_retry_seconds(exc: Exception, default: float = 15.0) -> float:
    """Read a provider-suggested backoff out of a rate-limit error message, or fall back to a default."""
    text = str(exc)
    for pattern in _RETRY_PATTERNS:
        match = pattern.search(text)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                continue
    return default


def _normalize(response):
    """Coerce response.content to a plain string regardless of provider format.

    Groq returns response.content as a plain string; Gemini can return a list
    of content blocks (e.g. [{'type': 'text', 'text': '...'}]). Every call
    site (research_agent.py, validator_agent.py) does response.content.strip()
    or slices it as a string, so both providers must present the same shape.
    """
    content = response.content
    if isinstance(content, list):
        content = "".join(
            block.get("text", "") if isinstance(block, dict) else str(block)
            for block in content
        )
    return SimpleNamespace(content=content)


class FallbackLLM:
    """Primary Groq client with automatic fallback to Google AI Studio.

    Both call sites (research_agent.py, validator_agent.py) invoke this
    exactly like a normal LangChain chat model -- .invoke(messages) -- so the
    fallback is transparent to agent logic and doesn't change what's being
    tested. Falls back only when GOOGLE_API_KEY is configured; otherwise
    Groq errors propagate exactly as before.
    """

    def __init__(self) -> None:
        self._primary = ChatGroq(
            model=MODEL_NAME,
            api_key=os.getenv("GROQ_API_KEY"),
            temperature=TEMPERATURE,
        )
        self._fallback = (
            ChatGoogleGenerativeAI(
                model=GOOGLE_MODEL_NAME,
                google_api_key=os.getenv("GOOGLE_API_KEY"),
                temperature=TEMPERATURE,
            )
            if os.getenv("GOOGLE_API_KEY")
            else None
        )

    def invoke(self, messages, max_attempts: int = 10):
        """Try Groq, then Gemini, alternating with provider-suggested backoff on rate limits.

        A single fallback attempt isn't enough when both providers are on
        free-tier quotas that can each be exhausted independently (Groq's is
        a rolling daily cap, Gemini's is a low per-minute cap) -- this keeps
        an unattended batch run alive by waiting out whichever provider is
        currently throttled rather than crashing on the first double-failure.
        """
        providers = [(self._primary, "Groq")]
        if self._fallback is not None:
            providers.append((self._fallback, f"Google AI Studio ({GOOGLE_MODEL_NAME})"))

        last_exc: Exception | None = None
        for attempt in range(max_attempts):
            client, name = providers[attempt % len(providers)]
            try:
                return _normalize(client.invoke(messages))
            except Exception as exc:
                last_exc = exc
                wait = _extract_retry_seconds(exc)
                print(
                    f"[LLM] {name} call failed ({exc.__class__.__name__}); "
                    f"waiting {wait:.0f}s before retry {attempt + 1}/{max_attempts}"
                )
                time.sleep(wait)
        raise last_exc


def get_llm() -> FallbackLLM:
    """Return the primary Groq client, transparently falling back to Google AI Studio on failure."""
    return FallbackLLM()
