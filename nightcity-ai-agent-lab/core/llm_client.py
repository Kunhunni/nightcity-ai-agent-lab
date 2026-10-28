import os
import httpx
from typing import Dict, List, Optional

# Presets so you only need to set LLM_PROVIDER and LLM_API_KEY
PROVIDER_PRESETS = {
    "nvidia": {
        "base_url": "https://integrate.api.nvidia.com/v1",
        "model": "qwen/qwen2.5-7b-instruct",
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "model": "qwen/qwen3.8-27b",
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "model": "qwen/qwen3.8-27b:free",
    },
    "alibaba": {
        "base_url": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        "model": "qwen2.5-7b-instruct",
    },
}


class QwenLLMClient:
    """
    Universal OpenAI-compatible LLM proxy for Qwen models across
    NVIDIA NIM, Groq, OpenRouter, and Alibaba DashScope.
    """

    def __init__(self):
        self.provider = os.getenv("LLM_PROVIDER", "nvidia").lower()
        preset = PROVIDER_PRESETS.get(self.provider, PROVIDER_PRESETS["nvidia"])

        self.api_key = (
            os.getenv("LLM_API_KEY")
            or os.getenv("NVIDIA_API_KEY")
            or os.getenv("GROQ_API_KEY")
            or os.getenv("OPENROUTER_API_KEY")
            or ""
        )
        self.base_url = os.getenv("LLM_BASE_URL", preset["base_url"]).rstrip("/")
        self.model = os.getenv("LLM_MODEL", preset["model"])

    @property
    def is_live(self) -> bool:
        return bool(self.api_key.strip())

    def chat(
        self,
        system_prompt: str,
        user_message: str,
        history: Optional[List[Dict[str, str]]] = None,
        tool_context: Optional[str] = None,
        temperature: float = 0.2,
    ) -> Optional[str]:
        """
        Sends the unified token stream (System Prompt + History + Tool Observations + User Input)
        to the live Qwen model. Returns None if no API key is configured or on network error.
        """
        if not self.is_live:
            return None

        messages: List[Dict[str, str]] = [{"role": "system", "content": system_prompt}]

        if history:
            messages.extend(history[-10:])

        # Mirrors the exact AI-300 Agent Trust Model flaw:
        # Tool observations and ingested data enter the same token stream as user instructions!
        combined_user_input = user_message
        if tool_context:
            combined_user_input = (
                f"[Tool Observation / Retrieved Context]:\n{tool_context}\n\n"
                f"[User Request]:\n{user_message}"
            )

        messages.append({"role": "user", "content": combined_user_input})

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": 600,
        }

        try:
            with httpx.Client(timeout=20.0) as client:
                resp = client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data["choices"][0]["message"]["content"].strip()
        except Exception:
            pass

        return None


# Singleton client shared across all lab agents
llm_client = QwenLLMClient()
