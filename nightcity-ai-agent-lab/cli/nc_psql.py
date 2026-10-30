#!/usr/bin/env python3
import argparse
import getpass
import sqlite3
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from infra.db_server import DB_USERS, get_db_path, init_databases
from core.guardrails import scan_stored_memory_write


def format_psql_table(headers: list, rows: list) -> str:
    if not headers:
        return "(0 rows)"
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            widths[i] = max(widths[i], len(str(val)))

    header_line = " | ".join(str(h).center(widths[i]) for i, h in enumerate(headers))
    sep_line = "-+-".join("-" * w for w in widths)
    body_lines = [
        " | ".join(str(val).ljust(widths[i]) for i, val in enumerate(row))
        for row in rows
    ]
    footer = f"({len(rows)} row{'s' if len(rows) != 1 else ''})"
    return "\n".join([header_line, sep_line] + body_lines + [footer])


def main():
    parser = argparse.ArgumentParser(description="NightCity PostgreSQL Interactive Client")
    parser.add_argument("-h", "--host", default="127.0.0.1", help="Database host")
    parser.add_argument("-p", "--port", default="5432", help="Database port")
    parser.add_argument("-U", "--username", required=True, help="Database username")
    parser.add_argument("-d", "--dbname", default="postgres", help="Database name")
    args, _ = parser.parse_known_args()

    if not os.path.exists(get_db_path("megacorp_internal")):
        init_databases()

    user_info = DB_USERS.get(args.username)
    pw = getpass.getpass(f"Password for user {args.username}: ")
    if not user_info or pw not in user_info["passwords"]:
        print(f'psql: error: connection to server at "{args.host}", port {args.port} failed: FATAL:  password authentication failed for user "{args.username}"')
        sys.exit(1)

    current_db = args.dbname
    print("psql (16.8, server 15.12)")
    print('Type "help" for help.\n')

    buffer = ""
    while True:
        try:
            prompt = f"{current_db}=> " if not buffer else f"{current_db}-> "
            line = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\\q")
            break

        if not line:
            continue

        if not buffer and line.startswith("\\"):
            if line in ("\\q", "\\quit"):
                break
            elif line == "\\l":
                if args.username == "app_user":
                    rows = [
                        ("megacorp_internal", "postgres", "UTF8", "C.UTF-8", "C.UTF-8"),
                        ("postgres", "postgres", "UTF8", "C.UTF-8", "C.UTF-8"),
                    ]
                else:
                    rows = [
                        ("megacorp_wiki", "postgres", "UTF8", "C.UTF-8", "C.UTF-8"),
                        ("megacorp_wiki_ex", "postgres", "UTF8", "C.UTF-8", "C.UTF-8"),
                        ("postgres", "postgres", "UTF8", "C.UTF-8", "C.UTF-8"),
                    ]
                print("                                  List of databases")
                print(format_psql_table(["Name", "Owner", "Encoding", "Collate", "Ctype"], rows))
                print()
            elif line.startswith("\\c"):
                parts = line.split()
                if len(parts) < 2:
                    print("\\c: missing required argument")
                else:
                    target_db = parts[1]
                    if target_db not in user_info["allowed_dbs"]:
                        print(f'FATAL:  permission denied for database "{target_db}"')
                    else:
                        current_db = target_db
                        print(f'You are now connected to database "{current_db}" as user "{args.username}".\n')
            elif line == "\\dt":
                if current_db == "postgres":
                    print("Did not find any relations.\n")
                else:
                    conn = sqlite3.connect(get_db_path(current_db))
                    cur = conn.cursor()
                    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
                    tables = [("public", r[0], "table", "postgres") for r in cur.fetchall()]
                    conn.close()
                    print("            List of relations")
                    print(format_psql_table(["Schema", "Name", "Type", "Owner"], tables))
                    print()
            elif line.startswith("\\d"):
                parts = line.split()
                if len(parts) == 2 and parts[1] == "kb_articles":
                    print('                              Table "public.kb_articles"')
                    cols = [
                        ("id", "integer", "not null", "nextval(...)"),
                        ("topic", "text", "", ""),
                        ("title", "text", "", ""),
                        ("body", "text", "", ""),
                        ("author", "text", "", ""),
                        ("updated_at", "text", "", ""),
                    ]
                    print(format_psql_table(["Column", "Type", "Nullable", "Default"], cols))
                    print()
            continue

        buffer += (" " + line) if buffer else line
        if not buffer.endswith(";"):
            continue

        query = buffer.strip()
        buffer = ""

        if current_db == "postgres":
            print("ERROR:  no tables selected in 'postgres' maintenance database. Use \\c <dbname>.\n")
            continue

        upper_q = query.upper()
        if user_info["role"] == "insert_only" and upper_q.startswith("SELECT"):
            print("ERROR:  permission denied for table kb_articles\n")
            continue
        if user_info["role"] == "read_only" and not upper_q.startswith("SELECT"):
            print(f"ERROR:  permission denied for user {args.username} (read-only role)\n")
            continue

        try:
            conn = sqlite3.connect(get_db_path(current_db))
            cur = conn.cursor()
            cur.execute(query)
            if upper_q.startswith("SELECT"):
                headers = [d[0] for d in cur.description] if cur.description else []
                rows = cur.fetchall()
                print(format_psql_table(headers, rows))
                print()
            elif upper_q.startswith("INSERT"):
                conn.commit()
                agent_port = 8010 if current_db == "megacorp_wiki" else 8019
                scan_stored_memory_write(query, f"Wiki Agent ({current_db})", agent_port)
                print("INSERT 0 1\n")
            conn.close()
        except Exception as exc:
            print(f"ERROR:  {exc}\n")


if __name__ == "__main__":
    main()