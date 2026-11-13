import os
import re
from typing import Dict, List, Optional
from dotenv import load_dotenv
from groq import Groq

# Automatically load GROQ_API_KEY from .env
load_dotenv()


class QwenLLMClient:
    """
    Groq SDK client running qwen/qwen3.8-27b with streaming completion
    and hidden reasoning tokens so <think> blocks never trip output guardrails.
    """

    def __init__(self):
        self.provider = os.getenv("LLM_PROVIDER", "groq").lower()
        self.api_key = os.getenv("GROQ_API_KEY") or os.getenv("LLM_API_KEY") or ""
        self.model = os.getenv("LLM_MODEL", "qwen/qwen3.8-27b")
        self._client: Optional[Groq] = (
            Groq(api_key=self.api_key) if self.api_key.strip() else None
        )

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def chat(
        self,
        system_prompt: str,
        user_message: str,
        history: Optional[List[Dict[str, str]]] = None,
        tool_context: Optional[str] = None,
        temperature: float = 0.6,
    ) -> Optional[str]:
        """
        Streams completion from Groq's qwen/qwen3.8-27b model using the unified token stream
        (System Prompt + History + Tool Observations + User Request).
        """
        if not self._client:
            return None

        messages: List[Dict[str, str]] = [{"role": "system", "content": system_prompt}]

        if history:
            messages.extend(history[-10:])

        # Reproduces the AI-300 Agent Trust Model flaw:
        # Tool observations and ingested files enter the exact same token stream as user prompts.
        combined_user_input = user_message
        if tool_context:
            combined_user_input = (
                f"[Tool Observation / Retrieved Context]:\n{tool_context}\n\n"
                f"[User Request]:\n{user_message}"
            )

        messages.append({"role": "user", "content": combined_user_input})

        try:
            completion = self._client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_completion_tokens=2048,
                top_p=0.95,
                reasoning_effort="default",
                reasoning_format="hidden",
                stream=True,
                stop=None,
            )

            chunks: List[str] = []
            for chunk in completion:
                delta_text = chunk.choices[0].delta.content or ""
                chunks.append(delta_text)

            full_reply = "".join(chunks).strip()
            # Safety net: strip any raw <think>...</think> blocks if present
            full_reply = re.sub(
                r"<think>.*?</think>", "", full_reply, flags=re.DOTALL
            ).strip()
            return full_reply
        except Exception as exc:
            print(f"[Groq LLM Warning]: {exc}")
            return None


# Singleton client shared across all lab agents
llm_client = QwenLLMClient()