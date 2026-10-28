import asyncio
import uvicorn
from core.llm_client import llm_client
from core.siem import create_siem_app
from agents.unit3_1_baseline import create_unit3_1_app


async def serve_app(app, port: int):
    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="warning")
    server = uvicorn.Server(config)
    await server.serve()


async def main():
    mode = (
        f"LIVE ({llm_client.provider.upper()} -> {llm_client.model})"
        if llm_client.is_live
        else "OFFLINE EMULATOR (Set GROQ_API_KEY in .env for live Qwen)"
    )
    print("=" * 72)
    print(" 🦾 NIGHTCITY AI AGENT LAB - RUNNING SERVICES")
    print("=" * 72)
    print(f" [*] LLM Engine : {mode}")
    print(" [*] Port 5601  : Elastic / Kibana SIEM Dashboard (http://127.0.0.1:5601)")
    print(" [*] Port 8001  : Unit 3.1 - Arasaka NetRunner Helpdesk (Baseline Agent)")
    print("=" * 72)
    print(" Press Ctrl+C to stop all services.\n")

    await asyncio.gather(
        serve_app(create_siem_app(), 5601),
        serve_app(create_unit3_1_app(), 8001),
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Shutting down NightCity AI Agent Lab.")