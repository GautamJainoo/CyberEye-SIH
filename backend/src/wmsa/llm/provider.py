"""
LLM Provider Abstraction for WMSA.
Local-first (Ollama/vLLM) with zero remote leakage by default.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

import httpx


class LLMProvider(ABC):
    """Abstract interface for local LLM inference engines."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Returns the identifier of the active model."""
        pass

    @abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generates raw completion text for the provided prompt."""
        pass


class MockLLMProvider(LLMProvider):
    """Deterministic mock provider for unit tests and offline CI runs."""

    def __init__(self, canned_response: Optional[str] = None, canned_responses: Optional[Dict[str, str]] = None):
        self._canned_response = canned_response
        self._canned_responses = canned_responses or {}
        self.last_prompt: Optional[str] = None
        self.last_system_prompt: Optional[str] = None

    @property
    def model_name(self) -> str:
        return "mock-local-q4:latest"

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        self.last_prompt = prompt
        self.last_system_prompt = system_prompt

        # Check for matching trigger in canned_responses
        for key, resp in self._canned_responses.items():
            if key in prompt:
                return resp

        if self._canned_response:
            return self._canned_response

        # Default structured JSON response
        return json.dumps({
            "summary": "Mock analysis of the target security finding.",
            "root_cause": "Unvalidated input handling in the affected handler.",
            "impact": "Potential confidentiality impact via unauthorized access.",
            "remediation": "Apply rigorous input validation and enforce authorization checks.",
            "diff_patch": "--- a/file.js\n+++ b/file.js\n@@ -1,2 +1,2 @@\n-untrusted()\n+trusted()",
        })


class OllamaProvider(LLMProvider):
    """Local Ollama engine provider strictly communicating over loopback."""

    def __init__(
        self,
        model: str = "llama3.2:latest",
        host: str = "http://127.0.0.1:11434",
        timeout: float = 30.0,
    ):
        self._model = model
        self.host = host.rstrip("/")
        self.timeout = timeout

    @property
    def model_name(self) -> str:
        return self._model

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        url = f"{self.host}/api/generate"
        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                return data.get("response", "")
        except Exception as e:
            raise RuntimeError(f"Ollama generation failed ({self.host}): {e}") from e
