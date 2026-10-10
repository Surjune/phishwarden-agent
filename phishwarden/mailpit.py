"""Thin client for the Mailpit REST API (https://mailpit.axllent.org/docs/api-v1/)."""

from typing import Any

import httpx

from phishwarden import config

_TIMEOUT = httpx.Timeout(10.0)


def _client() -> httpx.Client:
    return httpx.Client(base_url=config.MAILPIT_API, timeout=_TIMEOUT)


def search(query: str, limit: int = 200) -> list[dict[str, Any]]:
    with _client() as c:
        r = c.get("/search", params={"query": query, "limit": limit})
        r.raise_for_status()
        return r.json()["messages"]


def list_all(limit: int = 500) -> list[dict[str, Any]]:
    with _client() as c:
        r = c.get("/messages", params={"limit": limit})
        r.raise_for_status()
        return r.json()["messages"]


def get_message(message_id: str) -> dict[str, Any]:
    with _client() as c:
        r = c.get(f"/message/{message_id}")
        r.raise_for_status()
        return r.json()


def get_headers(message_id: str) -> dict[str, list[str]]:
    with _client() as c:
        r = c.get(f"/message/{message_id}/headers")
        r.raise_for_status()
        return r.json()


def set_tags(message_ids: list[str], tags: list[str]) -> None:
    with _client() as c:
        r = c.put("/tags", json={"IDs": message_ids, "Tags": tags})
        r.raise_for_status()


def delete_by_search(query: str) -> None:
    with _client() as c:
        r = c.delete("/search", params={"query": query})
        r.raise_for_status()


def delete_all() -> None:
    with _client() as c:
        r = c.request("DELETE", "/messages", json={"IDs": []})
        r.raise_for_status()
