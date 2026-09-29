"""
Groq (OpenAI-compatible) provider used to normalize and explain findings.

Only sanitized context (redacted code excerpt, rule metadata) is sent. The key is read from the
environment / backend/.env and is never logged or persisted.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

from wmsa.paths import get_base_dir

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_GROQ_MODEL = "openai/gpt-oss-120b"


def load_groq_key(base_dir: Optional[Path] = None) -> Optional[str]:
    key = os.environ.get("GROQ_API_KEY")
    if key:
        return key.strip()
    env_file = (base_dir or get_base_dir()) / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            m = re.match(r"\s*GROQ_API_KEY\s*=\s*(.+?)\s*$", line)
            if m:
                return m.group(1).strip("'\"")
    return None


class GroqProvider:
    def __init__(self, model: Optional[str] = None, timeout: float = 60.0, base_dir: Optional[Path] = None):
        self.model = model or os.environ.get("WMSA_GROQ_MODEL", DEFAULT_GROQ_MODEL)
        self.timeout = timeout
        self._key = load_groq_key(base_dir)

    @property
    def available(self) -> bool:
        return bool(self._key)

    def generate_json(self, system: str, user: str, max_tokens: int = 1400) -> Dict[str, Any]:
        if not self._key:
            raise RuntimeError("GROQ_API_KEY not configured")
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0.1,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }
        if "gpt-oss" in self.model:
            body["reasoning_effort"] = "low"  # ~5x faster; enough for structured explanations
        last = "unknown"
        for attempt in range(7):
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(GROQ_URL, json=body, headers={"Authorization": f"Bearer {self._key}"})
                if resp.status_code == 429:
                    # Groq states the wait in the header or in the message ("try again in 7.2s").
                    wait = 5.0 * (attempt + 1)
                    if resp.headers.get("retry-after"):
                        wait = float(resp.headers["retry-after"])
                    else:
                        m = re.search(r"try again in ([\d.]+)(ms|s)", resp.text)
                        if m:
                            wait = float(m.group(1)) / (1000 if m.group(2) == "ms" else 1)
                    last = "HTTP 429 rate limited"
                    time.sleep(min(wait + 1, 60))
                    continue
                if resp.status_code >= 500:
                    last = f"HTTP {resp.status_code}"
                    time.sleep(3 * (attempt + 1))
                    continue
                resp.raise_for_status()
                return json.loads(resp.json()["choices"][0]["message"]["content"])
            except (httpx.HTTPError, KeyError, ValueError) as e:
                last = f"{type(e).__name__}: {str(e)[:100]}"
                time.sleep(2)
        raise RuntimeError(f"Groq call failed: {last}")
