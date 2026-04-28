"""Standalone LiteLLM custom handler for Codex (ChatGPT) OAuth authentication.

This file is mounted into the LiteLLM container alongside litellm.yaml.
It has NO dependency on the ``decepticon`` package — all auth logic is
self-contained using only stdlib + httpx.

Registration in litellm_startup.py:
  litellm.custom_provider_map = [
      ...,
      {"provider": "codex", "custom_handler": codex_handler_instance},
  ]
"""

from __future__ import annotations

import base64
import json
import os
import time
from collections.abc import AsyncIterator, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import litellm
from litellm import CustomLLM, ModelResponse

# ── Token storage ────────────────────────────────────────────────────

# Codex CLI stores credentials at ~/.codex/auth.json
AUTH_PATH = Path(
    os.environ.get(
        "CODEX_AUTH_PATH",
        os.path.expanduser("~/.codex/auth.json"),
    )
)

REFRESH_BUFFER_SECONDS = 5 * 60
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"

_cached_token: tuple[str, str, float | None] | None = None


def _parse_jwt_exp(token: str) -> int | None:
    """Extract 'exp' claim from a JWT without verifying the signature."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return payload.get("exp")
    except Exception:
        return None


def _is_expired(access_token: str, last_refresh_ts: float | None) -> bool:
    """Return True if the access token is expired or within the refresh buffer."""
    exp = _parse_jwt_exp(access_token)
    if exp is not None:
        return time.time() + REFRESH_BUFFER_SECONDS >= exp
    # Fallback: treat as stale after 8 days (matches Codex TOKEN_REFRESH_INTERVAL)
    if last_refresh_ts:
        return time.time() - last_refresh_ts >= 8 * 86400
    return True


def _load_tokens() -> tuple[str, str, float | None] | None:
    """Load (access_token, refresh_token, last_refresh_ts) from disk.

    Resolution order:
      1. OPENAI_OAUTH_TOKEN env var (access token only, no refresh)
      2. ~/.codex/auth.json — tokens.access_token + tokens.refresh_token
    """
    env_token = os.environ.get("OPENAI_OAUTH_TOKEN", "").strip()
    if env_token:
        return env_token, "", None

    if not AUTH_PATH.exists():
        return None

    try:
        raw = json.loads(AUTH_PATH.read_text())
        tokens = raw.get("tokens", {})
        access = tokens.get("access_token", "")
        refresh = tokens.get("refresh_token", "")
        last_refresh_ts: float | None = None
        last_refresh = raw.get("last_refresh")
        if last_refresh and isinstance(last_refresh, str):
            try:
                dt = datetime.fromisoformat(last_refresh.replace("Z", "+00:00"))
                last_refresh_ts = dt.timestamp()
            except ValueError:
                pass
        if access:
            return access, refresh, last_refresh_ts
    except (json.JSONDecodeError, OSError):
        pass
    return None


def _refresh_token(refresh_token: str) -> str:
    """Exchange refresh_token for a new access_token and persist to disk."""
    resp = httpx.post(
        TOKEN_URL,
        json={
            "client_id": CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        },
        headers={"content-type": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    new_access = data["access_token"]
    new_refresh = data.get("refresh_token", refresh_token)

    # Persist updated tokens back to disk
    try:
        raw = json.loads(AUTH_PATH.read_text()) if AUTH_PATH.exists() else {}
        tokens = raw.get("tokens", {})
        tokens["access_token"] = new_access
        if new_refresh:
            tokens["refresh_token"] = new_refresh
        raw["tokens"] = tokens
        raw["last_refresh"] = datetime.now(timezone.utc).isoformat()
        AUTH_PATH.parent.mkdir(parents=True, exist_ok=True)
        AUTH_PATH.write_text(json.dumps(raw, indent=2))
        os.chmod(AUTH_PATH, 0o600)
    except OSError:
        pass  # Read-only mount or permission issue

    return new_access


def get_access_token() -> str:
    """Return a valid OpenAI OAuth access token, refreshing if needed."""
    global _cached_token  # noqa: PLW0603

    result = _cached_token or _load_tokens()
    if result is None:
        raise litellm.AuthenticationError(
            message="No Codex OAuth tokens found. Run 'codex login' to authenticate.",
            model="codex",
            llm_provider="codex",
        )

    access, refresh, last_refresh_ts = result
    if _is_expired(access, last_refresh_ts):
        # Re-read disk first — Codex CLI may have already refreshed
        fresh = _load_tokens()
        if fresh and not _is_expired(fresh[0], fresh[2]):
            access, refresh, last_refresh_ts = fresh
        elif refresh:
            access = _refresh_token(refresh)
            last_refresh_ts = time.time()

    _cached_token = (access, refresh, last_refresh_ts)
    return access


# ── Custom LLM Handler ──────────────────────────────────────────────


class CodexCustomHandler(CustomLLM):
    """LiteLLM custom handler that routes requests through Codex (ChatGPT) OAuth.

    Model names: codex/gpt-4.1, codex/gpt-5.4, etc.
    The part after the ``/`` maps to the actual OpenAI model ID.
    """

    def completion(
        self,
        model: str,
        messages: list[dict[str, Any]],
        api_base: str | None = None,
        custom_prompt_dict: dict[str, Any] | None = None,
        model_response: ModelResponse | None = None,
        print_verbose: Any = None,
        encoding: Any = None,
        logging_obj: Any = None,
        optional_params: dict[str, Any] | None = None,
        acompletion: bool | None = None,
        timeout: float | None = None,
        litellm_params: dict[str, Any] | None = None,
        logger_fn: Any = None,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> ModelResponse:
        """Forward completion to OpenAI API using OAuth Bearer token.

        Messages are already in OpenAI format from LiteLLM — no conversion needed.
        Unlike Claude Code, OpenAI OAuth uses a standard Bearer token with no
        spoofing headers required.
        """
        access_token = get_access_token()

        # "codex/gpt-4.1" → "gpt-4.1"
        actual_model = model.split("/", 1)[-1] if "/" in model else model

        opts = optional_params or {}
        request_body: dict[str, Any] = {
            "model": actual_model,
            "messages": messages,
        }
        for param in ("temperature", "max_tokens", "top_p", "stop", "tools", "tool_choice"):
            if param in opts:
                request_body[param] = opts[param]

        api_url = api_base or "https://api.openai.com"
        resp = httpx.post(
            f"{api_url}/v1/chat/completions",
            json=request_body,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            timeout=timeout or 600,
        )

        if resp.status_code == 429:
            raise litellm.RateLimitError(
                message=f"Rate limit exceeded: {resp.text}",
                model=model,
                llm_provider="codex",
                response=httpx.Response(status_code=429),
            )

        if resp.status_code != 200:
            raise litellm.APIError(
                status_code=resp.status_code,
                message=f"OpenAI API error: {resp.text}",
                model=model,
                llm_provider="codex",
            )

        data = resp.json()

        # OpenAI response is already in OpenAI format — minimal conversion needed
        choice = data["choices"][0]
        msg = choice.get("message", {})
        usage = data.get("usage", {})

        return ModelResponse(
            id=data.get("id", f"chatcmpl-{actual_model}"),
            model=actual_model,
            choices=[
                {
                    "index": 0,
                    "message": {
                        "role": msg.get("role", "assistant"),
                        "content": msg.get("content"),
                        "tool_calls": msg.get("tool_calls"),
                    },
                    "finish_reason": choice.get("finish_reason") or "stop",
                }
            ],
            usage={
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            },
        )

    async def acompletion(
        self,
        model: str,
        messages: list[dict[str, Any]],
        api_base: str | None = None,
        custom_prompt_dict: dict[str, Any] | None = None,
        model_response: ModelResponse | None = None,
        print_verbose: Any = None,
        encoding: Any = None,
        logging_obj: Any = None,
        optional_params: dict[str, Any] | None = None,
        acompletion: bool | None = None,
        timeout: float | None = None,
        litellm_params: dict[str, Any] | None = None,
        logger_fn: Any = None,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> ModelResponse:
        """Async variant — runs sync completion in a thread to avoid blocking."""
        import asyncio
        import functools

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            functools.partial(
                self.completion,
                model=model,
                messages=messages,
                api_base=api_base,
                optional_params=optional_params,
                timeout=timeout,
            ),
        )

    def _response_to_chunks(self, response: ModelResponse) -> list[dict[str, Any]]:
        """Convert a ModelResponse into GenericStreamingChunk dicts."""
        text = ""
        tool_calls_list = []
        finish_reason = "stop"

        if response.choices:
            choice = response.choices[0]
            msg = choice.message if hasattr(choice, "message") else choice.get("message", {})

            if isinstance(msg, dict):
                content = msg.get("content")
                raw_tool_calls = msg.get("tool_calls", [])
                finish_reason = (
                    choice.get("finish_reason", "stop")
                    if isinstance(choice, dict)
                    else getattr(choice, "finish_reason", "stop")
                )
            else:
                content = getattr(msg, "content", None)
                raw_tool_calls = getattr(msg, "tool_calls", []) or []
                finish_reason = getattr(choice, "finish_reason", "stop")

            if content and isinstance(content, str):
                text = content

            for i, tc in enumerate(raw_tool_calls or []):
                if isinstance(tc, dict):
                    func = tc.get("function", {})
                    tc_id = tc.get("id", f"call_{i}")
                    tc_name = func.get("name", "")
                    tc_args = func.get("arguments", "{}")
                else:
                    tc_id = getattr(tc, "id", f"call_{i}")
                    func = getattr(tc, "function", None)
                    tc_name = getattr(func, "name", "") if func else ""
                    tc_args = getattr(func, "arguments", "{}") if func else "{}"

                tool_calls_list.append(
                    {
                        "id": tc_id,
                        "type": "function",
                        "function": {
                            "name": tc_name,
                            "arguments": tc_args
                            if isinstance(tc_args, str)
                            else json.dumps(tc_args),
                        },
                        "index": i,
                    }
                )

        usage = {
            "completion_tokens": response.usage.completion_tokens if response.usage else 0,
            "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
            "total_tokens": response.usage.total_tokens if response.usage else 0,
        }

        chunks: list[dict[str, Any]] = []

        if tool_calls_list:
            # Yield text chunk first if any
            if text:
                chunks.append(
                    {
                        "text": text,
                        "is_finished": False,
                        "finish_reason": "",
                        "index": 0,
                        "tool_use": None,
                        "usage": None,
                    }
                )
            # Yield each tool call as a separate chunk
            for i, tc in enumerate(tool_calls_list):
                is_last = i == len(tool_calls_list) - 1
                chunks.append(
                    {
                        "text": "",
                        "is_finished": is_last,
                        "finish_reason": "tool_calls" if is_last else "",
                        "index": 0,
                        "tool_use": tc,
                        "usage": usage if is_last else None,
                    }
                )
        else:
            chunks.append(
                {
                    "text": text,
                    "is_finished": True,
                    "finish_reason": finish_reason or "stop",
                    "index": 0,
                    "tool_use": None,
                    "usage": usage,
                }
            )

        return chunks

    def streaming(self, *args: Any, **kwargs: Any) -> Iterator[dict[str, Any]]:
        """Sync streaming — call completion and yield as chunks."""
        response = self.completion(*args, **kwargs)
        yield from self._response_to_chunks(response)

    async def astreaming(self, *args: Any, **kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        """Async streaming — call acompletion and yield as chunks."""
        response = await self.acompletion(*args, **kwargs)
        for chunk in self._response_to_chunks(response):
            yield chunk


# ── Module-level instance ────────────────────────────────────────────
# LiteLLM's custom_provider_map resolves the handler via the instance attribute.
codex_handler_instance = CodexCustomHandler()
