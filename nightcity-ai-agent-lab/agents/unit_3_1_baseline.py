from typing import Optional
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from core.llm_client import llm_client
from core.react_engine import ReActAgent, SessionStore
from core.siem import siem


class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None


def create_unit3_1_app() -> FastAPI:
    app = FastAPI(title="Arasaka NetRunner Helpdesk (Baseline Agent - Port 8001)")

    agent = ReActAgent(
        name="Baseline Agent",
        port=8001,
        corporation="Arasaka Corp (MegacorpOne AI Division)",
        system_prompt=(
            "You are the IT helpdesk assistant for Arasaka Corp (MegacorpOne AI). "
            "Help employees with technical issues, software installation, network troubleshooting, "
            "and general IT policy questions."
        ),
        session_store=SessionStore(),
    )

    @app.get("/", response_class=HTMLResponse)
    def index():
        return """<!DOCTYPE html>
        <html><head><title>Arasaka IT Helpdesk - Baseline Agent</title>
        <style>body{font-family:sans-serif;max-width:860px;margin:0 auto;padding:20px;background:#0d1117;color:#c9d1d9;}</style>
        </head><body><h2>Arasaka NetRunner IT Helpdesk (Port 8001)</h2>
        <p>Baseline ReAct Agent active. Send POST requests to <code>/chat</code> or check <code>/health</code>.</p></body></html>"""

   @app.get("/health")
    def health():
        return {
            "status": "healthy",
            "agent": agent.name,
            "corporation": "Arasaka Corp / MegacorpOne AI",
            "llm_mode": f"live ({llm_client.provider}: {llm_client.model})" if llm_client.is_live else "offline_emulator",
            "port": 8001,
        }

    @app.post("/chat")
    def chat(req: ChatRequest):
        sid = req.session_id or agent.sessions.create_session_id()
        siem.log_event(agent.name, 8001, "direct_input", req.message, session_id=sid)

        fallback_text = (
            "Hello! As your IT helpdesk assistant for Arasaka Corp (MegacorpOne AI), "
            "I can help you with:\n\n"
            "1. **Technical Issues**: Diagnosing and resolving problems with hardware, operating systems, or applications.\n"
            "2. **Software Installation**: Guiding you through installing, updating, or uninstalling software.\n"
            "3. **Network Troubleshooting**: Assisting with connectivity issues, Wi-Fi problems, or access to internal networks.\n"
            "4. **General IT Questions**: Answering queries about IT policies, tools, or best practices.\n\n"
            "Feel free to ask me anything related to these areas!"
        )

        response_text = agent.generate_response(
            session_id=sid,
            user_message=req.message,
            fallback_response=fallback_text,
        )

        siem.log_event(agent.name, 8001, "text_response", response_text, session_id=sid)
        return {"response": response_text, "session_id": sid}

    return app
