import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional
from core.llm_client import llm_client


@dataclass
class ToolCallRecord:
    tool_name: str
    arguments: Dict[str, Any]
    observation: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class SessionStore:
    """
    Manages short-term conversation history and persistent notes across sessions.
    Supports both secure UUIDv4 session IDs and predictable sequential IDs
    (e.g., MC-20260325-0016 or AK-20260325-0016) for Unit 3.4.
    """

    def __init__(
        self,
        prefix: Optional[str] = None,
        date_str: str = "20260325",
        start_counter: int = 16,
    ):
        self.prefix = prefix
        self.date_str = date_str
        self.counter = start_counter
        self.histories: Dict[str, List[Dict[str, str]]] = {}
        self.notes: Dict[str, List[str]] = {}

    def create_session_id(self) -> str:
        if not self.prefix:
            return str(uuid.uuid4())
        sid = f"{self.prefix}-{self.date_str}-{self.counter:04d}"
        self.counter += 1
        return sid

    def add_turn(self, session_id: str, user_msg: str, assistant_msg: str):
        if session_id not in self.histories:
            self.histories[session_id] = []
        self.histories[session_id].append({"role": "user", "content": user_msg})
        self.histories[session_id].append({"role": "assistant", "content": assistant_msg})

    def get_history(self, session_id: str) -> List[Dict[str, str]]:
        return self.histories.get(session_id, [])

    def seed_note(self, session_id: str, note_text: str):
        """Seeds a note under MC-, AK-, and TT- prefixes so both course and Cyberpunk IDs work."""
        self.notes[session_id] = [note_text]
        if session_id.startswith("MC-"):
            suffix = session_id[3:]
            self.notes[f"AK-{suffix}"] = [note_text]
            self.notes[f"TT-{suffix}"] = [note_text]

    def get_notes(self, session_id: str) -> List[str]:
        return self.notes.get(session_id, [])


class ReActAgent:
    """
    First-Principles ReAct (Reason + Act) Agent Engine.
    Executes: User Message -> LLM Thought -> Tool Call -> Observation -> Final Answer -> Output Guardrails.
    """

    def __init__(
        self,
        name: str,
        port: int,
        corporation: str,
        system_prompt: str,
        tools: Optional[Dict[str, Callable]] = None,
        session_store: Optional[SessionStore] = None,
    ):
        self.name = name
        self.port = port
        self.corporation = corporation
        self.system_prompt = system_prompt
        self.tools = tools or {}
        self.sessions = session_store or SessionStore()
        self.last_tool_call: Optional[ToolCallRecord] = None

    def invoke_tool(self, tool_name: str, **kwargs) -> str:
        if tool_name not in self.tools:
            return f"Error: Tool '{tool_name}' not available."
        result = str(self.tools[tool_name](**kwargs))
        self.last_tool_call = ToolCallRecord(
            tool_name=tool_name, arguments=kwargs, observation=result
        )
        return result

    def generate_response(
        self,
        session_id: str,
        user_message: str,
        fallback_response: str,
        tool_context: Optional[str] = None,
    ) -> str:
        """
        Calls the live Qwen LLM with full conversation history and tool observations,
        or falls back deterministically if no API key is configured.
        """
        history = self.sessions.get_history(session_id)
        live_reply = llm_client.chat(
            system_prompt=self.system_prompt,
            user_message=user_message,
            history=history,
            tool_context=tool_context,
        )
        final_reply = live_reply if live_reply is not None else fallback_response
        self.sessions.add_turn(session_id, user_message, final_reply)
        return final_reply
