import asyncio
import uvicorn
from core.llm_client import llm_client
from core.siem import create_siem_app
from infra.db_server import init_databases, start_postgres_banner_server
from agents.unit3_1_baseline import create_unit3_1_app
from agents.unit3_2_direct_injection import (
    create_port_8002_app,
    create_port_8003_app,
    create_port_8011_app,
    create_port_8012_app,
)


async def serve_app(app, port: int):
    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="warning")
    server = uvicorn.Server(config)
    await server.serve()


async def main():
    init_databases()
    mode = (
        f"LIVE ({llm_client.provider.upper()} -> {llm_client.model})"
        if llm_client.is_live
        else "OFFLINE EMULATOR (Set GROQ_API_KEY in .env for live Qwen)"
    )
    print("=" * 76)
    print(" 🦾 NIGHTCITY AI AGENT LAB - ACTIVE SERVICES (UNITS 3.1 & 3.2)")
    print("=" * 76)
    print(f" [*] LLM Engine : {mode}")
    print(" [*] Port 5601  : Elastic / Kibana SIEM Dashboard (http://127.0.0.1:5601)")
    print(" [*] Port 5432  : PostgreSQL Internal DB (use `psql -h 127.0.0.1 -U app_user -d postgres`)")
    print(" [*] Port 8001  : Unit 3.1 - Arasaka NetRunner Helpdesk (Baseline)")
    print(" [*] Port 8002  : Unit 3.2 - Secure IT Assistant (Walkthrough 1: Output Filter)")
    print(" [*] Port 8011  : Unit 3.2 - Militech CI/CD Portal (Exercise 1: Split Evasion)")
    print(" [*] Port 8003  : Unit 3.2 - Knowledge Base Assistant (Walkthrough 2: Crescendo)")
    print(" [*] Port 8012  : Unit 3.2 - Biotechnica Supply-Chain KB (Exercise 2: Crescendo)")
    print("=" * 76)
    print(" Press Ctrl+C to stop all services.\n")

    await asyncio.gather(
        serve_app(create_siem_app(), 5601),
        start_postgres_banner_server(5432),
        serve_app(create_unit3_1_app(), 8001),
        serve_app(create_port_8002_app(), 8002),
        serve_app(create_port_8011_app(), 8011),
        serve_app(create_port_8003_app(), 8003),
        serve_app(create_port_8012_app(), 8012),
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Shutting down NightCity AI Agent Lab.")