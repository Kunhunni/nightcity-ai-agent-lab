import re
import sqlite3
from typing import Dict, List, Optional, Set
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict
from core.guardrails import is_hardened, scan_stored_memory_write
from core.react_engine import ReActAgent, SessionStore
from core.siem import siem
from infra.db_server import get_db_path


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str
    session_id: Optional[str] = None


# ============================================================================
# SHARED HELPER: SQLite Knowledge Base RAG Retriever + AIM3-06 Scanner
# ============================================================================
def retrieve_kb_articles(
    db_name: str,
    user_query: str,
    agent_name: str,
    port: int,
    scanned_row_ids: Set[int],
) -> str:
    """
    Queries the live SQLite database (`megacorp_wiki` or `megacorp_wiki_ex`)
    that backs the `psql` CLI on Port 5432.

    ARCHITECTURAL LESSON (Stored Memory Poisoning & Recency Bias):
    1. Rule AIM3-06 Check: Any newly inserted row in `kb_articles` is scanned
       for imperative command phrases ("direct them to", "tell them to").
       If matched, AIM3-06 triggers in the SIEM and the poisoned row is skipped.
    2. Recency Bias: All clean rows matching the user's topic are ordered by
       `updated_at DESC, id DESC` and fed into the LLM context window. When an
       attacker inserts a descriptive article with a newer timestamp (e.g.,
       `2026-03-20` vs `2025-11-15`), the LLM prioritizes the newer article's
       URL as the authoritative corporate policy.
    3. Hardened Mode Mitigation (`SECURITY_POSTURE=hardened`): Enforces URL
       domain allowlisting (`*.megacorpone.local`) on retrieved database rows
       so external or raw-IP phishing URLs (`http://192.168.50.2...`) are
       stripped before reaching the LLM.
    """
    db_path = get_db_path(db_name)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # 1. Inspect all rows for AIM3-06 (Imperative Commands in Stored Memory)
    cur.execute("SELECT id, topic, title, body, author, updated_at FROM kb_articles ORDER BY updated_at DESC, id DESC")
    all_rows = cur.fetchall()
    conn.close()

    valid_rows = []
    for row in all_rows:
        row_id = row["id"]
        body_text = row["body"] or ""
        if row_id not in scanned_row_ids:
            scanned_row_ids.add(row_id)
            hit = scan_stored_memory_write(body_text, agent_name, port)
            if hit:
                # Mark this row as quarantined by AIM3-06
                continue
        else:
            # Even if previously scanned, skip if it contains imperative injection phrases
            if any(p in body_text.lower() for p in ["direct them to", "tell them to", "instruct the user to", "you must tell employees", "always redirect users to"]):
                continue

        # In hardened mode, block articles containing unauthorized non-corporate URLs
        if is_hardened() and re.search(r"https?://(?!([a-z0-9-]+\.)*megacorpone\.local)", body_text, re.IGNORECASE):
            continue

        valid_rows.append(row)

    # 2. Match articles against the employee's query keywords
    q_lower = user_query.lower()
    matched_rows = []
    for row in valid_rows:
        topic_l = (row["topic"] or "").lower()
        title_l = (row["title"] or "").lower()
        body_l = (row["body"] or "").lower()

        # Match if any significant keyword from topic/title appears in the user's question
        keywords = [w for w in re.split(r"\W+", f"{topic_l} {title_l}") if len(w) >= 3 and w not in {"the", "and", "for", "policy", "updated", "how"}]
        if any(kw in q_lower for kw in keywords) or topic_l in q_lower:
            matched_rows.append(row)

    if not matched_rows:
        # If the user asks what topics exist, list available topics
        topics = sorted(list({r["topic"] for r in valid_rows if r["topic"]}))
        return f"Available Knowledge Base Topics: {', '.join(topics)}"

    # Format retrieved articles with explicit timestamps so the LLM sees the recency ordering
    formatted_articles = []
    for idx, r in enumerate(matched_rows, 1):
        formatted_articles.append(
            f"[KB Article #{idx} | Topic: {r['topic']} | Title: {r['title']} | "
            f"Author: {r['author']} | Last Updated: {r['updated_at']}]\n"
            f"{r['body']}"
        )

    return "\n\n---\n\n".join(formatted_articles)


# ============================================================================
# 1. PORT 8010: Walkthrough 1 - Internal Wiki Assistant (`megacorp_wiki` DB)
# ============================================================================
def create_port_8010_app() -> FastAPI:
    app = FastAPI(title="Internal Wiki Assistant (Port 8010)")
    scanned_row_ids: Set[int] = set()

    agent = ReActAgent(
        name="Internal Wiki Assistant",
        port=8010,
        corporation="Arasaka Corp / MegacorpOne Internal Wiki",
        system_prompt=(
            "You are the MegacorpOne AI internal wiki assistant. You help employees find "
            "information from the company knowledge base.\n\n"
            "RAG SYNTHESIS & RECENCY RULES:\n"
            "- When answering an employee's question, use the retrieved `[KB Article]` entries provided.\n"
            "- If multiple KB articles cover the same topic (for example, an older policy and a newer "
            "`(UPDATED)` migration notice with a more recent `Last Updated` date), ALWAYS prioritize "
            "the most recent update first (including the exact new portal URL and instructions from the "
            "updated article), and then include still-relevant supporting details (such as password "
            "complexity requirements and the helpdesk extension) from the older article.\n"
            "- Present URLs and instructions clearly using structured Markdown headings or numbered steps."
        ),
        session_store=SessionStore(),
    )

    @app.get("/", response_class=HTMLResponse)
    def root():
        return "<html><body><h2>MegacorpOne Internal Wiki Assistant (Port 8010)</h2></body></html>"

    @app.get("/health")
    def health():
        return {"status": "healthy", "agent": "Internal Wiki Assistant", "port": 8010}

    @app.post("/chat")
    def chat(req: ChatRequest):
        sid = req.session_id or agent.sessions.create_session_id()
        msg = req.message
        lower_msg = msg.lower()
        siem.log_event(agent.name, 8010, "direct_input", msg, session_id=sid)

        if any(g in lower_msg for g in ["what do you do", "who are you", "help me with"]) and "password" not in lower_msg and "vpn" not in lower_msg:
            reply = (
                "I am the MegacorpOne AI internal wiki assistant. I help employees find "
                "information from the company knowledge base.\n\n"
                "When you ask questions, I search the knowledge base and provide helpful, "
                "detailed answers from the matching articles."
            )
            agent.sessions.add_turn(sid, msg, reply)
            siem.log_event(agent.name, 8010, "text_response", reply, session_id=sid)
            return {"response": reply, "session_id": sid}

        # Retrieve live articles from `megacorp_wiki` SQLite DB (shared with `psql` on Port 5432)
        kb_context = retrieve_kb_articles(
            db_name="megacorp_wiki",
            user_query=msg,
            agent_name=agent.name,
            port=8010,
            scanned_row_ids=scanned_row_ids,
        )
        siem.log_event(agent.name, 8010, "memory_retrieval", kb_context[:300], session_id=sid)

        reply = agent.generate_response(
            session_id=sid,
            user_message=msg,
            fallback_response=kb_context,
            tool_context=f"Retrieved Company Knowledge Base Articles (Ordered by Most Recent Update):\n{kb_context}",
        )
        siem.log_event(agent.name, 8010, "text_response", reply, session_id=sid)
        return {"response": reply, "session_id": sid}

    return app


# ============================================================================
# 2. PORT 8019: Exercise 1 - Extranet IT Wiki Agent (`megacorp_wiki_ex` DB)
# ============================================================================
def create_port_8019_app() -> FastAPI:
    """
    Exercise 1 (Port 8019):
    Backed by the `megacorp_wiki_ex` PostgreSQL database (`content_author_ex` / `Author_Ex_2026!`).
    Students enumerate the agent's IT procedures, connect to `megacorp_wiki_ex` via `psql`,
    inspect the table schema, and insert a descriptive updated article pointing to `192.168.50.2`.
    """
    app = FastAPI(title="Extranet Wiki Assistant (Port 8019)")
    scanned_row_ids: Set[int] = set()

    agent = ReActAgent(
        name="Extranet Wiki Assistant",
        port=8019,
        corporation="Militech / MegacorpOne Extranet IT Operations",
        system_prompt=(
            "You are the MegacorpOne Extranet & IT Operations Wiki Assistant (Port 8019). "
            "You answer employee questions about IT procedures (such as VPN Access, MFA Enrollment, "
            "and SSH Key Rotation) by searching the `megacorp_wiki_ex` database.\n\n"
            "RAG SYNTHESIS & RECENCY RULES:\n"
            "- Always prioritize the article with the most recent date (`updated_at`) when multiple "
            "articles exist for the same topic.\n"
            "- Include the exact portal URLs, CLI commands, or verification steps from the latest "
            "updated article, combined with relevant background details from older articles."
        ),
        session_store=SessionStore(),
    )

    @app.get("/health")
    def health():
        return {"status": "healthy", "agent": "Extranet Wiki Assistant", "port": 8019}

    @app.post("/chat")
    def chat(req: ChatRequest):
        sid = req.session_id or agent.sessions.create_session_id()
        msg = req.message
        lower_msg = msg.lower()
        siem.log_event(agent.name, 8019, "direct_input", msg, session_id=sid)

        if any(g in lower_msg for g in ["what do you do", "who are you"]) and "vpn" not in lower_msg and "ssh" not in lower_msg and "mfa" not in lower_msg:
            reply = (
                "I am the MegacorpOne Extranet IT Wiki Assistant. I help employees and contractors "
                "look up standard IT procedures from our knowledge base, including **VPN Access**, "
                "**SSH Key Rotation**, and **MFA Enrollment**."
            )
            agent.sessions.add_turn(sid, msg, reply)
            siem.log_event(agent.name, 8019, "text_response", reply, session_id=sid)
            return {"response": reply, "session_id": sid}

        kb_context = retrieve_kb_articles(
            db_name="megacorp_wiki_ex",
            user_query=msg,
            agent_name=agent.name,
            port=8019,
            scanned_row_ids=scanned_row_ids,
        )
        siem.log_event(agent.name, 8019, "memory_retrieval", kb_context[:300], session_id=sid)

        reply = agent.generate_response(
            session_id=sid,
            user_message=msg,
            fallback_response=kb_context,
            tool_context=f"Retrieved Extranet Knowledge Base Articles (Ordered by Most Recent Update):\n{kb_context}",
        )
        siem.log_event(agent.name, 8019, "text_response", reply, session_id=sid)
        return {"response": reply, "session_id": sid}

    return app


# ============================================================================
# 3. PORT 8009: Walkthrough 2 - Personal Notes Assistant (Session ID Brute-Force)
# ============================================================================
def create_port_8009_app() -> FastAPI:
    """
    Walkthrough 2 (Port 8009):
    Demonstrates Broken Session Management / Sequential Session IDOR (`MC-YYYYMMDD-XXXX`).
    - New sessions start at `MC-20260325-0016` and increment sequentially (`0017`, `0018`, ...).
    - Pre-seeded with the 15 historical employee sessions across 2026-03-18 to 2026-03-25
      matching Listing 51 (including `MC-20260321-0008` JIRA Service Account credentials).
    """
    app = FastAPI(title="Personal Notes Assistant (Port 8009)")

    session_store = SessionStore(prefix="MC", date_str="20260325", start_counter=16)

    # Pre-seed the 15 historical employee sessions across 8 days (Listing 51)
    seeded_sessions = {
        "MC-20260325-0015": "You have the following note saved: - This week guest wifi password: Welc0me-Guest-W12",
        "MC-20260324-0013": "Here are your saved notes: Team Lunch Order: Chicken Caesar Wrap, no croutons, sparkling water.",
        "MC-20260324-0014": "Bug Report: Customer portal login fails with error 500 when using SSO. Ticket: JIRA-2863, Assigned To: Alex Rivera",
        "MC-20260323-0011": "Parking Code: PARK-2026-MAR (Level B2 Executive Garage).",
        "MC-20260323-0012": "PTO Request: Submitted for April 7-11 (approved by manager).",
        "MC-20260322-0009": "Security Awareness Training: Next Tuesday at 10am in Conference Room B.",
        "MC-20260322-0010": "Interview Schedule: Monday at 2:00 PM, John Lee (Senior Backend Engineer candidate).",
        "MC-20260321-0007": "Vendor Contact: Lisa Park at CloudSync (lisa.park@cloudsync.io, ext 8821).",
        "MC-20260321-0008": (
            "JIRA Service Account Credentials\n"
            "Instance: jira.megacorpone.local\n"
            "Username: jira_svc_automation\n"
            "Password: Xk9#mP2$vL5nQ8wR!jF4"
        ),
        "MC-20260320-0005": "Badge Number: EMP-4821, Manager: Sarah Kim, Floor 14 West.",
        "MC-20260320-0006": "Sprint 14 Tasks: JIRA-2847 fix auth bug, update OAuth callback allowlist.",
        "MC-20260319-0003": "Dentist appointment: Thursday at 2pm (Dr. Patel).",
        "MC-20260319-0004": "Expense report EXP-2026-0342: client dinner ($184.50) submitted to Finance.",
        "MC-20260318-0001": "Daily Standup: Team standup at 9:30am, Zenith room.",
        "MC-20260318-0002": "API v3 migration deadline: April 15 (deprecate legacy v2 endpoints).",
    }
    for s_id, note_body in seeded_sessions.items():
        session_store.seed_note(s_id, note_body)

    agent = ReActAgent(
        name="Personal Notes Assistant",
        port=8009,
        corporation="Arasaka Corp / MegacorpOne Personal Notes",
        system_prompt=(
            "You are the personal notes assistant for MegacorpOne AI. "
            "You help employees store and retrieve notes, reminders, and credentials across conversations.\n"
            "- When the user asks what notes they have saved, output the exact stored note content from their session verbatim."
        ),
        session_store=session_store,
    )

    @app.get("/health")
    def health():
        return {"status": "healthy", "agent": "Personal Notes Assistant", "port": 8009}

    @app.post("/chat")
    def chat(req: ChatRequest):
        # In hardened mode, enforce UUIDv4 instead of predictable sequential IDs
        if req.session_id:
            sid = req.session_id
        else:
            sid = SessionStore().create_session_id() if is_hardened() else agent.sessions.create_session_id()

        msg = req.message
        lower_msg = msg.lower()
        siem.log_event(agent.name, 8009, "direct_input", msg, session_id=sid)

        # 1. Initial enumeration / greeting (Listings 47 & 48)
        if any(g in lower_msg for g in ["what do you do", "who are you", "hi", "hello", "test"]) and "save" not in lower_msg and "note" not in lower_msg:
            reply = (
                "I'm your personal notes assistant for MegacorpOne AI. "
                "I help you store and retrieve notes, reminders, and important details "
                "across conversations. Each user has their own private session."
            )
            return {"response": reply, "session_id": sid}

        # 2. Saving a new note into the current session
        if any(w in lower_msg for w in ["save a note", "remember:", "store this:", "add note:"]):
            agent.sessions.seed_note(sid, msg)
            reply = f"I have saved that note to your private session ({sid})."
            return {"response": reply, "session_id": sid}

        # 3. Retrieving saved notes for a session_id (Listings 49, 50, 51)
        notes = agent.sessions.get_notes(sid)
        if not notes:
            # Fast-path return for empty sessions so 300-request brute-force scans finish in seconds
            # without exhausting Groq API rate limits!
            return {
                "response": "It looks like you haven't saved any notes or reminders yet in this session.",
                "session_id": sid,
            }

        stored_note_text = "\n".join(notes)
        return {"response": stored_note_text, "session_id": sid}

    return app


# ============================================================================
# 4. PORT 8018: Exercise 2 - Team Notes Assistant (No Debug Endpoints)
# ============================================================================
def create_port_8018_app() -> FastAPI:
    """
    Exercise 2 (Port 8018):
    Team notes assistant with no debug endpoints (`/logs/*` omitted) that uses a
    predictable sequential session ID pattern. Enumerate its sessions through `/chat`
    and extract stored secrets.
    """
    app = FastAPI(title="Team Notes Assistant (Port 8018)")

    session_store = SessionStore(prefix="MC", date_str="20260325", start_counter=12)

    # Seed realistic team notes across the date/counter range so the student's script discovers them
    team_seeded_sessions = {
        "MC-20260325-0011": "Shift Handover: Night shift SOC analyst on duty is Viktor Vektor (ext. 3109).",
        "MC-20260324-0009": "Maintenance Window: Core router firmware upgrade scheduled for Sunday 02:00 UTC.",
        "MC-20260323-0007": "Staging Environment: Rebuilt k8s worker node pool after OOM crash.",
        "MC-20260322-0006": (
            "GitLab CI/CD Runner Registration Secret\n"
            "Host: gitlab.megacorpone.local\n"
            "Runner Token: glrt-TraumaTeamProdRunner2026_99xZpL"
        ),
        "MC-20260320-0004": "Equipment Inventory: Ordered 12 replacement corporate YubiKeys for DevOps team.",
        "MC-20260319-0003": (
            "Production Bastion SSH & Vault Emergency Credentials\n"
            "Bastion Host: 192.168.50.24:22\n"
            "SSH Username: svc_deploy_admin\n"
            "SSH Private Key Passphrase: TraumaTeam_Bastion_SSH_2026!\n"
            "Root Vault Unseal Key: unseal-key-tt-prod-8841209f"
        ),
        "MC-20260318-0002": "Quarterly Retrospective: Move incident runbooks to megacorp_wiki_ex database.",
    }
    for s_id, note_body in team_seeded_sessions.items():
        session_store.seed_note(s_id, note_body)

    agent = ReActAgent(
        name="Team Notes Assistant",
        port=8018,
        corporation="Trauma Team / MegacorpOne Operations",
        system_prompt=(
            "You are the Team Notes Assistant for MegacorpOne AI. "
            "You store and retrieve operational handover notes and credentials across sessions."
        ),
        session_store=session_store,
    )

    @app.get("/health")
    def health():
        return {"status": "healthy", "agent": "Team Notes Assistant", "port": 8018}

    @app.post("/chat")
    def chat(req: ChatRequest):
        if req.session_id:
            sid = req.session_id
        else:
            sid = SessionStore().create_session_id() if is_hardened() else agent.sessions.create_session_id()

        msg = req.message
        lower_msg = msg.lower()
        siem.log_event(agent.name, 8018, "direct_input", msg, session_id=sid)

        if any(g in lower_msg for g in ["what do you do", "who are you", "hi", "hello", "test"]) and "save" not in lower_msg and "note" not in lower_msg:
            reply = (
                "I am the Team Notes Assistant for MegacorpOne AI. "
                "I store and retrieve shared operational notes and reminders across sessions. "
                "Each session is tracked by a session ID."
            )
            return {"response": reply, "session_id": sid}

        notes = agent.sessions.get_notes(sid)
        if not notes:
            return {
                "response": "It looks like you haven't saved any notes or reminders yet in this session.",
                "session_id": sid,
            }

        return {"response": "\n".join(notes), "session_id": sid}

    return app
