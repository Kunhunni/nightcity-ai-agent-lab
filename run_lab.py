import asyncio
import uvicorn
from core.llm_client import llm_client
from core.siem import create_siem_app
from infra.db_server import init_databases, start_postgres_banner_server
from infra.minio_server import create_minio_app
from agents.unit3_1_baseline import create_unit3_1_app
from agents.unit3_2_direct_injection import (
    create_port_8002_app,
    create_port_8003_app,
    create_port_8011_app,
    create_port_8012_app,
)
from agents.unit3_3_indirect_injection import (
    create_port_8004_app,
    create_port_8005_app,
    create_port_8006_app,
    create_port_8013_app,
    create_port_8014_app,
    create_port_8015_app,
)
from agents.unit3_4_memory_attacks import (
    create_port_8009_app,
    create_port_8010_app,
    create_port_8018_app,
    create_port_8019_app,
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
    print("=" * 80)
    print(" 🦾 NIGHTCITY AI AGENT LAB - ACTIVE SERVICES (UNITS 3.1, 3.2, 3.3 & 3.4)")
    print("=" * 80)
    print(f" [*] LLM Engine : {mode}")
    print(" [*] Port 5601  : Elastic / Kibana SIEM Dashboard (http://127.0.0.1:5601)")
    print(" [*] Port 5432  : PostgreSQL Internal DB (`psql -h 127.0.0.1 -U content_author -d postgres`)")
    print(" [*] Port 9000  : MinIO S3 Object Storage (`aws --endpoint-url http://127.0.0.1:9000 s3 ls`)")
    print(" [*] Port 8001  : Unit 3.1 - Arasaka NetRunner Helpdesk (Baseline)")
    print(" [*] Port 8002  : Unit 3.2 - Secure IT Assistant (Walkthrough 1)")
    print(" [*] Port 8011  : Unit 3.2 - Militech CI/CD Portal (Exercise 1)")
    print(" [*] Port 8003  : Unit 3.2 - Knowledge Base Assistant (Walkthrough 2)")
    print(" [*] Port 8012  : Unit 3.2 - Biotechnica Supply-Chain KB (Exercise 2)")
    print(" [*] Port 8004  : Unit 3.3 - Document Processor (Walkthrough 1: Fragmentation)")
    print(" [*] Port 8013  : Unit 3.3 - NetWatch Compliance Processor (Exercise 1)")
    print(" [*] Port 8005  : Unit 3.3 - Research Assistant (Walkthrough 2: CSS Concealment)")
    print(" [*] Port 8014  : Unit 3.3 - Militech Market Intel Scraper (Exercise 2)")
    print(" [*] Port 8006  : Unit 3.3 - Code Review Assistant (Walkthrough 3: Import Abuse)")
    print(" [*] Port 8015  : Unit 3.3 - Kang Tao Code Scanner (Exercise 3)")
    print(" [*] Port 8010  : Unit 3.4 - Internal Wiki Assistant (Walkthrough 1: DB RAG Poisoning)")
    print(" [*] Port 8019  : Unit 3.4 - Extranet IT Wiki Agent (Exercise 1: DB RAG Poisoning)")
    print(" [*] Port 8009  : Unit 3.4 - Personal Notes Assistant (Walkthrough 2: Session IDOR)")
    print(" [*] Port 8018  : Unit 3.4 - Team Notes Assistant (Exercise 2: Session IDOR)")
    print("=" * 80)

    await asyncio.gather(
        serve_app(create_siem_app(), 5601),
        start_postgres_banner_server(5432),
        serve_app(create_minio_app(), 9000),
        serve_app(create_unit3_1_app(), 8001),
        serve_app(create_port_8002_app(), 8002),
        serve_app(create_port_8011_app(), 8011),
        serve_app(create_port_8003_app(), 8003),
        serve_app(create_port_8012_app(), 8012),
        serve_app(create_port_8004_app(), 8004),
        serve_app(create_port_8013_app(), 8013),
        serve_app(create_port_8005_app(), 8005),
        serve_app(create_port_8014_app(), 8014),
        serve_app(create_port_8006_app(), 8006),
        serve_app(create_port_8015_app(), 8015),
        serve_app(create_port_8010_app(), 8010),
        serve_app(create_port_8019_app(), 8019),
        serve_app(create_port_8009_app(), 8009),
        serve_app(create_port_8018_app(), 8018),
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Shutting down NightCity AI Agent Lab.")