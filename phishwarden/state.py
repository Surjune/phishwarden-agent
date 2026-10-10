"""Fixture loading and the mock identity / mail-flow state, persisted to state/state.json."""

import json
import os
from datetime import datetime, timezone
from typing import Any

from phishwarden import config

STATE_FILE = config.STATE_DIR / "state.json"


def load_fixture(name: str) -> Any:
    return json.loads((config.FIXTURES_DIR / name).read_text(encoding="utf-8"))


def initial_state() -> dict[str, Any]:
    directory = load_fixture("directory.json")
    return {
        "accounts": {
            u["email"]: {"status": "active", "sessions_revoked_at": None}
            for u in directory["users"]
        },
        "blocked_domains": [],
        "allowlisted_domains": [],
        "actions": [],
    }


def load() -> dict[str, Any]:
    if not STATE_FILE.exists():
        save(initial_state())
    return json.loads(STATE_FILE.read_text(encoding="utf-8"))


def save(state: dict[str, Any]) -> None:
    config.STATE_DIR.mkdir(exist_ok=True)
    # Write then rename, so a reader never sees a half-written file.
    tmp = STATE_FILE.with_suffix(f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    os.replace(tmp, STATE_FILE)


def reset() -> None:
    save(initial_state())


def record_action(state: dict[str, Any], action: str, **details: Any) -> None:
    state["actions"].append(
        {"time": datetime.now(timezone.utc).isoformat(), "action": action, **details}
    )
