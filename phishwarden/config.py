"""Runtime settings, read from the environment (and `.env` when present)."""

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

FIXTURES_DIR = ROOT / "fixtures"
STATE_DIR = ROOT / "state"
RUNS_DIR = ROOT / "runs"

# Mailpit listens on IPv4 loopback only. "localhost" would try ::1 first, and on Windows
# a refused connection takes about two seconds before the IPv4 fallback.
MAILPIT_API = os.getenv("MAILPIT_API", "http://127.0.0.1:8025/api/v1")
MAILPIT_SMTP_HOST = os.getenv("MAILPIT_SMTP_HOST", "127.0.0.1")
MAILPIT_SMTP_PORT = int(os.getenv("MAILPIT_SMTP_PORT", "1025"))

MCP_HOST = os.getenv("MCP_HOST", "127.0.0.1")
MCP_PORT = int(os.getenv("MCP_PORT", "8000"))
DIRECT_MCP_URL = f"http://{MCP_HOST}:{MCP_PORT}/mcp"
# Interface the MCP server listens on. On a Linux host the AgntID container reaches the
# server through the Docker bridge, not loopback, so a server deployment sets 0.0.0.0
# (with the port closed in the firewall) while clients still connect via MCP_HOST.
MCP_BIND_HOST = os.getenv("MCP_BIND_HOST", MCP_HOST)

# Where each agent sends its tool calls. Pointing these at the AgntID runtime proxy is the
# only change between the "before" and "after" runs.
TRIAGE_MCP_URL = os.getenv("TRIAGE_MCP_URL", DIRECT_MCP_URL)
RESPONSE_MCP_URL = os.getenv("RESPONSE_MCP_URL", DIRECT_MCP_URL)

# AgntID runtime proxy endpoints used by the dashboard's "after" run.
AGNTID_TRIAGE_MCP_URL = os.getenv("AGNTID_TRIAGE_MCP_URL", "")
AGNTID_RESPONSE_MCP_URL = os.getenv("AGNTID_RESPONSE_MCP_URL", "")

# Model provider: "gemini" (default) or "claude".
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-opus-5-5")
MAX_AGENT_TURNS = int(os.getenv("PHISHWARDEN_MAX_TURNS", "25"))

QUARANTINE_TAG = "quarantined"
SOC_SENDER = "soc-automation@acme.example"
