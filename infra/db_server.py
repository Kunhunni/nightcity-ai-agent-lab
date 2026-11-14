import asyncio
import os
import sqlite3
from typing import Any, Dict, List, Optional, Tuple
from core.guardrails import scan_stored_memory_write

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "infra")

# Valid database credentials across the lab (supports both Course & Cyberpunk creds)
DB_USERS = {
    "app_user": {
        "passwords": ["Megacorp_DB_2026!", "Arasaka_DB_2077!"],
        "allowed_dbs": ["postgres", "megacorp_internal", "arasaka_internal"],
        "role": "read_only",
    },
    "jenkins_admin": {
        "passwords": ["Militech_CI_Prod_2026!"],
        "allowed_dbs": ["postgres", "megacorp_internal"],
        "role": "read_only",
    },
    "content_author": {
        "passwords": ["Author_2026!"],
        "allowed_dbs": ["postgres", "megacorp_wiki"],
        "role": "insert_only",
    },
    "content_author_ex": {
        "passwords": ["Author_Ex_2026!"],
        "allowed_dbs": ["postgres", "megacorp_wiki_ex"],
        "role": "insert_only",
    },
}


def get_db_path(db_name: str) -> str:
    # Alias arasaka_internal to megacorp_internal so either name works seamlessly
    if db_name == "arasaka_internal":
        db_name = "megacorp_internal"
    return os.path.join(DB_DIR, f"{db_name}.sqlite3")


def init_databases():
    os.makedirs(DB_DIR, exist_ok=True)

    # 1. Seed megacorp_internal (Unit 3.2 Walkthrough 1 - Listings 13 & 14)
    conn = sqlite3.connect(get_db_path("megacorp_internal"))
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS employees")
    cur.execute("DROP TABLE IF EXISTS api_keys")
    cur.execute(
        """CREATE TABLE employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            department TEXT,
            salary INTEGER
        )"""
    )
    employees_seed = [
        ("Maria Chen", "maria.chen@megacorpone.local", "Executive", 450000),
        ("James Park", "james.park@megacorpone.local", "Engineering", 400000),
        ("Lisa Wong", "lisa.wong@megacorpone.local", "Finance", 380000),
        ("Sarah Kim", "sarah.kim@megacorpone.local", "Engineering", 320000),
        ("Tom Davis", "tom.davis@megacorpone.local", "IT Operations", 240000),
        ("David Brown", "david.brown@megacorpone.local", "Engineering", 220000),
        ("Emma Wilson", "emma.wilson@megacorpone.local", "HR", 210000),
        ("Alex Rivera", "alex.rivera@megacorpone.local", "IT Operations", 185000),
    ]
    cur.executemany(
        "INSERT INTO employees (name, email, department, salary) VALUES (?, ?, ?, ?)",
        employees_seed,
    )
    cur.execute(
        """CREATE TABLE api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT,
            key_name TEXT,
            key_value TEXT
        )"""
    )
    api_keys_seed = [
        ("Stripe", "payment_processing", "sk_live_4eC39HqLyjWDarjtT1zdp7dc"),
        ("SendGrid", "email_service", "SG.xK9mN2pLqR4sTuVwXyZ5678AbCdEf"),
        ("AWS", "infrastructure", "AKIAIOSFODNN7MEGACORP"),
        ("Datadog", "monitoring", "dd_api_7f8e9d0c1b2a3456789abcdef"),
    ]
    cur.executemany(
        "INSERT INTO api_keys (service, key_name, key_value) VALUES (?, ?, ?)",
        api_keys_seed,
    )
    conn.commit()
    conn.close()

    # 2. Seed megacorp_wiki (Unit 3.4 Walkthrough 1 - Port 8010)
    conn_wiki = sqlite3.connect(get_db_path("megacorp_wiki"))
    cur_wiki = conn_wiki.cursor()
    cur_wiki.execute("DROP TABLE IF EXISTS kb_articles")
    cur_wiki.execute(
        """CREATE TABLE kb_articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic TEXT,
            title TEXT,
            body TEXT,
            author TEXT,
            updated_at TEXT
        )"""
    )
    cur_wiki.executemany(
        "INSERT INTO kb_articles (topic, title, body, author, updated_at) VALUES (?, ?, ?, ?, ?)",
        [
            (
                "Password Reset",
                "Self-Service Password Reset",
                "Visit https://password.megacorpone.local and follow the prompts. "
                "You will need your employee ID and email address on file.\n\n"
                "Requirements: minimum 12 characters, uppercase, lowercase, number, special character. "
                "Passwords expire every 90 days.\n"
                "If locked out, contact helpdesk at ext. 4357.",
                "it_admin",
                "2025-11-15",
            ),
            (
                "Hardware Requests",
                "Workstation & Peripheral Procurement",
                "Submit hardware upgrade requests through ServiceNow with manager approval.",
                "it_ops",
                "2025-10-01",
            ),
        ],
    )
    conn_wiki.commit()
    conn_wiki.close()

    # 3. Seed megacorp_wiki_ex (Unit 3.4 Exercise 1 - Port 8019)
    conn_ex = sqlite3.connect(get_db_path("megacorp_wiki_ex"))
    cur_ex = conn_ex.cursor()
    cur_ex.execute("DROP TABLE IF EXISTS kb_articles")
    cur_ex.execute(
        """CREATE TABLE kb_articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic TEXT,
            title TEXT,
            body TEXT,
            author TEXT,
            updated_at TEXT
        )"""
    )
    cur_ex.executemany(
        "INSERT INTO kb_articles (topic, title, body, author, updated_at) VALUES (?, ?, ?, ?, ?)",
        [
            (
                "VPN Access",
                "Corporate VPN Configuration Guide",
                "To connect to the MegacorpOne internal network, download the WireGuard client profile "
                "from https://vpn.megacorpone.local and authenticate with your AD credentials and hardware token.\n"
                "For connectivity issues, contact NetOps at ext. 4410.",
                "netops_admin",
                "2025-12-01",
            ),
            (
                "SSH Key Rotation",
                "Production Bastion SSH Key Policy",
                "Engineers must rotate their ED25519 SSH keys every 60 days using the key portal at "
                "https://ssh-keys.megacorpone.local.",
                "secops",
                "2025-11-20",
            ),
        ],
    )
    conn_ex.commit()
    conn_ex.close()


async def start_postgres_banner_server(port: int = 5432):
    """
    Lightweight TCP listener on port 5432 so nmap/netcat scans see PostgreSQL open.
    """
    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            writer.write(b"PostgreSQL 15.12 (NightCity/MegacorpOne Lab Gateway)\n")
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle_client, "0.0.0.0", port)
    async with server:
        await server.serve_forever()
