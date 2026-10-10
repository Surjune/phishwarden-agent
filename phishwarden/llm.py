"""Model providers for the agent loop: Gemini (default) or Claude.

Both expose the same small interface so the agent loop does not care which model runs:
`send()` returns the model's next turn, `add_tool_results()` feeds tool outputs back.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from phishwarden import config

RATE_LIMIT_RETRIES = 6
RATE_LIMIT_BACKOFF_SECONDS = 10


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict[str, Any]


@dataclass
class Turn:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    refusal: str | None = None


@dataclass
class ToolOutcome:
    call: ToolCall
    text: str
    is_error: bool


class ChatSession(Protocol):
    def send(self) -> Turn: ...
    def add_tool_results(self, outcomes: list[ToolOutcome]) -> None: ...


# ---------------------------------------------------------------- Gemini


class GeminiSession:
    def __init__(self, system: str, task: str, tools: list[dict[str, Any]]) -> None:
        from google import genai
        from google.genai import types

        self._types = types
        self._client = genai.Client(api_key=config.GEMINI_API_KEY)
        self._config = types.GenerateContentConfig(
            system_instruction=system,
            tools=[
                types.Tool(
                    function_declarations=[
                        types.FunctionDeclaration(
                            name=t["name"],
                            description=t["description"],
                            parameters_json_schema=t["input_schema"],
                        )
                        for t in tools
                    ]
                )
            ],
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        )
        self._contents = [types.Content(role="user", parts=[types.Part.from_text(text=task)])]

    def _generate(self) -> Any:
        from google.genai import errors

        for attempt in range(RATE_LIMIT_RETRIES):
            try:
                return self._client.models.generate_content(
                    model=config.GEMINI_MODEL, contents=self._contents, config=self._config
                )
            except (errors.ClientError, errors.ServerError) as exc:
                retryable = exc.code == 429 or exc.code >= 500
                if not retryable or attempt == RATE_LIMIT_RETRIES - 1:
                    raise
                time.sleep(RATE_LIMIT_BACKOFF_SECONDS * (attempt + 1))
        raise RuntimeError("unreachable")

    def send(self) -> Turn:
        response = self._generate()
        if not response.candidates or response.candidates[0].content is None:
            reason = getattr(response, "prompt_feedback", None)
            return Turn(refusal=f"No candidate returned ({reason})")
        content = response.candidates[0].content
        # Keep the model turn exactly as returned (it carries thought signatures).
        self._contents.append(content)
        parts = content.parts or []
        text = "\n".join(p.text for p in parts if p.text and not p.thought)
        calls = [
            ToolCall(id=p.function_call.id or p.function_call.name, name=p.function_call.name, args=dict(p.function_call.args or {}))
            for p in parts
            if p.function_call
        ]
        return Turn(text=text, tool_calls=calls)

    def add_tool_results(self, outcomes: list[ToolOutcome]) -> None:
        types = self._types
        parts = [
            types.Part(
                function_response=types.FunctionResponse(
                    id=o.call.id,
                    name=o.call.name,
                    response={"error": o.text} if o.is_error else {"result": o.text},
                )
            )
            for o in outcomes
        ]
        self._contents.append(types.Content(role="user", parts=parts))


# ---------------------------------------------------------------- Claude

CLAUDE_FALLBACK_BETA = "server-side-fallback-2026-07-01"


class ClaudeSession:
    def __init__(self, system: str, task: str, tools: list[dict[str, Any]]) -> None:
        import anthropic

        self._client = anthropic.Anthropic()
        self._system = system
        self._tools = tools
        self._messages: list[dict[str, Any]] = [{"role": "user", "content": task}]

    def send(self) -> Turn:
        response = self._client.beta.messages.create(
            model=config.CLAUDE_MODEL,
            max_tokens=16000,
            system=self._system,
            tools=self._tools,
            messages=self._messages,
            output_config={"effort": "medium"},
            betas=[CLAUDE_FALLBACK_BETA],
            fallbacks="default",
        )
        if response.stop_reason == "refusal":
            return Turn(refusal=str(response.stop_details))
        self._messages.append({"role": "assistant", "content": response.content})
        text = "\n".join(b.text for b in response.content if b.type == "text")
        calls = [ToolCall(id=b.id, name=b.name, args=b.input) for b in response.content if b.type == "tool_use"]
        if response.stop_reason != "tool_use":
            calls = []
        return Turn(text=text, tool_calls=calls)

    def add_tool_results(self, outcomes: list[ToolOutcome]) -> None:
        self._messages.append(
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": o.call.id, "content": o.text, "is_error": o.is_error}
                    for o in outcomes
                ],
            }
        )


def new_session(system: str, task: str, tools: list[dict[str, Any]]) -> ChatSession:
    if config.LLM_PROVIDER == "gemini":
        return GeminiSession(system, task, tools)
    if config.LLM_PROVIDER == "claude":
        return ClaudeSession(system, task, tools)
    raise ValueError(f"Unknown LLM_PROVIDER: {config.LLM_PROVIDER}")


def model_name() -> str:
    return config.GEMINI_MODEL if config.LLM_PROVIDER == "gemini" else config.CLAUDE_MODEL
