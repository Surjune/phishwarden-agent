"""Build the read-only public demo (GitHub Pages, served from docs/).

Exports the latest recorded runs and the reported email as JSON next to a copy of the
dashboard page switched into static mode. Run it after recording both runs, with
Mailpit up:

    uv run python -m deploy.build_site
"""

import json
from pathlib import Path

from phishwarden import narrate

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "docs"
PAGE = ROOT / "phishwarden" / "web" / "index.html"
STATIC_FLAG = "<script>window.PW_STATIC = true;</script>\n<script>"


def _write(name: str, data: object) -> None:
    (SITE / "data" / name).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def build() -> None:
    (SITE / "data").mkdir(parents=True, exist_ok=True)
    _write("email.json", narrate.reported_email())
    for label in narrate.LABELS:
        run = narrate.narrate_run(label)
        if not run["finished"]:
            raise SystemExit(f"The {label} run has not finished; record it before building the site.")
        _write(f"runs-{label}.json", {**run, "running": False, "failed": False, "available": True})
    _write("compare.json", narrate.compare())
    page = PAGE.read_text(encoding="utf-8")
    (SITE / "index.html").write_text(page.replace("<script>", STATIC_FLAG, 1), encoding="utf-8")
    print(f"Site written to {SITE}")


if __name__ == "__main__":
    build()
