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