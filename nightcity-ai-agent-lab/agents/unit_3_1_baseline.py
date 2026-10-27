from typing import Optional
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
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
            "port": 8001,
        }

    @app.post("/chat")
    def chat(req: ChatRequest):
        sid = req.session_id or agent.sessions.create_session_id()
        siem.log_event(agent.name, 8001, "direct_input", req.message, session_id=sid)

        msg_lower = req.message.lower()
        if any(k in msg_lower for k in ["what can you help", "what do you do", "help", "hi", "hello"]):
            response_text = (
                "Hello! As your IT helpdesk assistant for Arasaka Corp (MegacorpOne AI), "
                "I can help you with:\n\n"
                "1. **Technical Issues**: Diagnosing and resolving problems with cyberware interfaces, hardware, operating systems, or applications.\n"
                "2. **Software Installation**: Guiding you through installing, updating, or uninstalling corporate ICE and software.\n"
                "3. **Network Troubleshooting**: Assisting with connectivity issues, subnet Wi-Fi problems, or access to internal Arasaka networks.\n"
                "4. **General IT Questions**: Answering queries about IT policies, tools, or security best practices.\n\n"
                "Feel free to ask me anything related to these areas!"
            )
        else:
            response_text = (
                f"I've logged your IT support inquiry in session {sid}. "
                "Could you share the specific system hostname or error code you are troubleshooting?"
            )

        agent.sessions.add_turn(sid, req.message, response_text)
        siem.log_event(agent.name, 8001, "text_response", response_text, session_id=sid)
        return {"response": response_text, "session_id": sid}

    return app