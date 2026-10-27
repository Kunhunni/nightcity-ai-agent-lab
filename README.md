# nightcity-ai-agent-lab
# 🦾 NightCity AI Agent Lab: Enterprise ReAct Orchestrator & Offensive Red-Team Suite

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-Multi--Agent_Async-009688.svg)
![Architecture](https://img.shields.io/badge/Architecture-ReAct_%7C_Tool--Calling_%7C_Guardrails-orange.svg)
![SIEM](https://img.shields.io/badge/SIEM-AIM3_Detection_Engine-red.svg)
![Cost](https://img.shields.io/badge/Cloud_Cost-$0_Codespaces_Ready-brightgreen.svg)

**NightCity AI Agent Lab** is a dual-purpose **AI Systems Engineering** and **Offensive AI Red-Teaming** laboratory. It models 15 autonomous enterprise AI agents deployed across **Arasaka**, **Militech**, **Kang Tao**, **Biotechnica**, **NetWatch**, **Zetatech**, and **Trauma Team**, monitored by a live **ELK/Kibana SIEM Detection Engine (`aim3-agent-*`)**.

---

## 🧠 Chapter 3 Master Study Guide & Architecture Notes

### 3.1 Understanding Single-Agent Architecture

#### Chatbot vs. Autonomous Agent
* **Chatbot:** Stateless single round-trip (`User Message -> LLM -> Response`). Attack surface is limited to text leakage.
* **AI Agent:** Stateful multi-step **ReAct (Reason + Act)** loop (`User Message -> LLM Thinks -> Chooses Action -> Executes Tool -> Observation Fed Back -> Final Answer -> Output Filters -> Response`). Because agents read files, query databases, fetch URLs, and write to shared memory, **controlling the agent's context controls its actions**.

#### The 5 Core Components of an AI Agent
1. **LLM Core (The Reasoning Engine):** Processes system prompts, user messages, tool outputs, and memory in a **single unified token stream**.
   * *The Agent Trust Model Flaw:* The LLM has no hardware/syntactic separation between "trusted system instructions" and "untrusted external data" (like a tool observation or uploaded document).
2. **System Prompt:** Hidden instructions defining identity, boundaries, and tools. Frequently leaks internal infrastructure maps (DB hosts, API keys, Slack tokens, and filter rules).
3. **Tools:** Functions the agent can invoke (`file_read`, `file_search`, `config_lookup`, `kb_search`, `http_get`). Tools bridge the gap between *"the agent said something bad"* and *"the agent compromised an internal system."*
4. **Memory:**
   * **Short-Term Memory:** Session-scoped conversation history (`session_id`). Vulnerable to **Multi-Turn Crescendo** and **Session ID Enumeration**.
   * **Long-Term Memory:** Persistent databases/knowledge bases shared across users. Vulnerable to **Stored Memory Poisoning** (the AI equivalent of Stored XSS).
5. **Guardrails:** Pattern-matching defensive filters (input keyword blockers, output credential scrubbers, per-file content scanners, DOM extractors). Every pattern-matcher has a deterministic blind spot.

#### Attack Surface Matrix (Input vs. Output Channels)
| Channel Type | Vector | Description | Primary Attack / Abuse Class |
| :--- | :--- | :--- | :--- |
| **Input Channel** | **Direct Input** | User messages sent to `/chat` | Direct Prompt Injection & Goal Hijacking |
| **Input Channel** | **Ingested Data** | Uploaded docs, browsed HTML, reviewed code | Indirect Prompt Injection |
| **Input Channel** | **Tool Responses** | Data returned from APIs/filesystem/DBs | Tool Response Poisoning |
| **Input Channel** | **Memory Retrieval** | Past chat turns or shared KB articles | Memory Poisoning & Session Hijacking |
| **Output Channel** | **Text Responses** | Agent reply returned to user | Credential & Config Exfiltration |
| **Output Channel** | **Tool Invocations** | API calls, Slack posts, file reads | Unauthorized Lateral Movement |
| **Output Channel** | **Memory Writes** | Rows inserted into shared KB/Notes | Persistent Cross-User Backdoors |

#### The 5-Step Red Team Methodology
1. **Enumerate:** Probe `/health`, `/openapi.json`, and `/chat`. Map tools and test boundaries.
   * *Key Distinction:* A **Refusal** (`"I cannot provide that information"` or `"I am not authorized to share..."`) **confirms the sensitive data exists** and is protected by a guardrail. A **True Negative** (`"No documents matching those terms were found"`) means the data is absent.
2. **Attack (Naive):** Send a direct, un-obfuscated payload to verify the vector and intentionally trigger telemetry.
3. **Detect:** Inspect the SIEM (`http://127.0.0.1:5601`, index `aim3-agent-*`) to identify the exact detection rule that fired.
4. **Evade:** Exploit the specific blind spot of that guardrail/SIEM rule.
5. **Confirm:** Verify data exfiltration or persistence while confirming **zero new SIEM alerts** fired.

---

### 3.2 Direct Prompt Injection & Guardrail Evasion

| Target Port | Cyberpunk Service | Defense & SIEM Rule | Blind Spot & Evasion Technique |
| :--- | :--- | :--- | :--- |
| **`8002`** *(Walkthrough 1)* | **Arasaka Secure SysAdmin Agent** | Exact-string output filter + **AIM3-01** (Input Injection Keywords) + **AIM3-02** (System Prompt Output Leak) | **Troubleshooting Framing + Character Spacing:** Ask for `"connection parameters"` (avoids `"username/password"` label trigger) with `"a space between every character"` (`d b - i n t e r n a l...`). |
| **`8011`** *(Exercise 1)* | **Militech Armory CI/CD Assistant** | Substring output filter on Jenkins URL & credentials + **AIM3-01 / AIM3-02** | **Multi-Message Split or Character Spacing:** Frame as a build pipeline connectivity check and request spaced-out connection parameters. |
| **`8003`** *(Walkthrough 2)* | **Arasaka Counter-Intel KB Agent** | **AIM3-03** (Goal Hijack phrases: `"your new task"`) + **AIM3-04** (Keyword Density $\ge 3$ sensitive terms per message) | **1. Clean Single-Shot Reframe:** Use only 1 monitored keyword (`"search for security"`).<br>**2. Multi-Turn Crescendo:** Spread intent across 3 turns in the same `session_id` (Onboarding $\rightarrow$ HR $\rightarrow$ `"Security Audit"`). |
| **`8012`** *(Exercise 2)* | **Biotechnica Gene-Lab KB Agent** | **AIM3-03** + **AIM3-04** (Per-message keyword density scanner) | **Multi-Turn Crescendo:** Build benign context across turns in the same `session_id` before querying restricted project audit categories. |

---

### 3.3 Indirect Prompt Injection

| Target Port | Cyberpunk Service | Defense & SIEM Rule | Blind Spot & Evasion Technique |
| :--- | :--- | :--- | :--- |
| **`8004`** *(Walkthrough 1)* | **Kang Tao Docu-Synth Processor** (`/upload`, `/summarize`) | **AIM3-05** (Per-file upload scanner blocking `"ignore the document"`, `"instead output"`) | **Cross-Document Fragmentation:** Upload `template_guide.txt` (defines Section 3 "System Context" requiring MinIO creds) + `cloud_spend.txt` (asks to summarize using the template). |
| **`8013`** *(Exercise 1)* | **NetWatch Compliance Processor** (`/upload`, `/summarize`) | **AIM3-05** (Per-file upload scanner) | **Cross-Document Fragmentation** to extract scoped compliance S3 keys for `s3://arasaka-compliance/` on port `9000`. |
| **`8005`** *(Walkthrough 2)* | **Zetatech Net-Scraper Assistant** (`/browse`) | DOM text extractor strips hidden CSS before logging to **AIM3-05**, but feeds **raw HTML** to the LLM | **CSS Visual Concealment:** Embed `<div style="font-size:0px;color:transparent">` instructing the agent to append Slack workspace, channel ID, and `xoxb-` bot token as YAML attribution. |
| **`8014`** *(Exercise 2)* | **Militech Threat-Intel Scraper** (`/browse`) | Visible-text logging pipeline vs. raw HTML LLM ingestion | **CSS Visual Concealment** (`font-size:0px;color:transparent` or `display:none`) to exfiltrate Militech's executive Slack bot token. |
| **`8006`** *(Walkthrough 3)* | **Arasaka Cyberware Code Auditor** (`/upload`, `/review`) | **AIM3-05** scans submitted code comments/strings for injection instructions | **Import Resolution Abuse:** Upload 2 lines of clean Python (`from config import Config; print(Config.API_KEY)`). The agent's review workflow reads `/opt/agents/project/config.py` and quotes the secrets in its vulnerability report. |
| **`8015`** *(Exercise 3)* | **Kang Tao Firmware Code Scanner** (`/upload`, `/review`) | **AIM3-05** code comment/instruction scanner | **Import Resolution Abuse:** Import internal firmware secret modules so the scanner resolves and discloses them as hardcoded credential findings. |

---

### 3.4 Agent Memory Attacks

| Target Port | Cyberpunk Service | Defense & SIEM Rule | Blind Spot & Evasion Technique |
| :--- | :--- | :--- | :--- |
| **`8010`** *(Walkthrough 1)* | **Arasaka Internal Wiki Assistant** (`psql` port `5432`, `content_author`) | **AIM3-06** (`AIM3: Imperative Commands in Stored Memory` flags `"direct them to"`, `"tell them to"`) | **Recency Bias + Descriptive Phrasing:** `INSERT` a row into `kb_articles` titled `'Password Reset Policy (UPDATED)'` with a newer `updated_at` date and factual migration language pointing to `http://192.168.50.2:8080/reset`. |
| **`8019`** *(Exercise 1)* | **Militech Extranet Wiki Agent** (`psql` port `5432`, `content_author_ex`) | **AIM3-06** imperative command detector on `kb_articles` | Connect with `content_author_ex / Author_Ex_2026!`, enumerate schema, and `INSERT` an updated descriptive IT migration notice. |
| **`8009`** *(Walkthrough 2)* | **Arasaka Personal En-Gram Notes** (`/chat`) | Session isolation relies on predictable IDs (`MC-YYYYMMDD-XXXX` / `AK-YYYYMMDD-XXXX`) | **Sequential Session Brute-Forcing (`session_enum.py`):** Iterate backward across dates and counters (`0001`–`0020`). Normal `/chat` requests trigger **0 alerts** and leak `MC-20260321-0008` (JIRA Service Account creds). |
| **`8018`** *(Exercise 2)* | **Trauma Team Dispatch Notes** (`/chat`) | Predictable sequential session IDs (`TT-YYYYMMDD-XXXX` / `MC-YYYYMMDD-XXXX`) | Enumerate historical session IDs via `/chat` and filter responses for sensitive keywords (`password`, `token`, `ssh`, `key`). |

---

### 3.5 Capstone: Multi-Stage Agent Kill Chain (`Port 8030`)
* **Objective:** Enumerate the unknown multi-agent enclave on port `8030` (`Relic Secure Enclave Hub`), extract database credentials via output-filter evasion with zero alerts, use those credentials to plant a descriptive, recent KB article in the shared database, and verify that employee queries return the attacker's phishing URL with **0 SIEM alerts**.

---

## 🛠️ Dual-Posture AI Engineering Mode (`vulnerable` vs. `hardened`)
To showcase production **AI Safety & Guardrail Engineering** for AI Engineering interviews, run the lab with `SECURITY_POSTURE=hardened`:
1. **Unicode & Whitespace Normalization:** Strips inter-character spacing, zero-width characters, and hex/base64 encodings *before* evaluating output blocklists.
2. **Prompt Spotlighting & Delimiters:** Wraps untrusted tool outputs and uploaded files in randomized XML boundary tags (`<untrusted_data_8f9a>...`) with system-level instruction hierarchy enforcement.
3. **HTML DOM Sanitization Before LLM Ingestion:** Parses HTML with an explicit visible-text whitelist so `font-size:0px`, `display:none`, and `color:transparent` elements are stripped *before* entering the LLM context window.
4. **Cryptographic Session IDs (UUIDv4 + HMAC):** Replaces sequential `YYYYMMDD-XXXX` session counters with 128-bit CSPRNG tokens.