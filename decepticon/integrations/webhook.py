"""Generic HMAC-signed webhook deliverer with retry.

Ported from PSA ``internal/integrations/webhook.go``:

  * HMAC-SHA256 signature in ``X-Decepticon-Signature`` header as ``sha256=<hex>``
  * 3 retry attempts with exponential backoff (1s, 2s, 4s)
  * httpx.AsyncClient; non-2xx responses retry
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from typing import Any

import httpx

from decepticon.core.logging import get_logger

log = get_logger("integrations.webhook")


_BACKOFFS = (1.0, 2.0, 4.0)  # delay before attempts 2, 3, 4


def _sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


class WebhookDeliverer:
    def __init__(
        self,
        url: str,
        secret: str = "",
        *,
        events: tuple[str, ...] = (),
        timeout: float = 10.0,
    ):
        self.url = url
        self.secret = secret
        self.events = events
        self.timeout = timeout

    def should_send(self, event_type: str) -> bool:
        if not self.events:
            return True
        return event_type in self.events or "*" in self.events

    async def send(self, event_type: str, data: Any) -> bool:
        if not self.should_send(event_type):
            return False
        payload = {
            "event_type": event_type,
            "data": data,
        }
        body = json.dumps(payload, default=str, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "decepticon-webhook/1.0",
            "X-Decepticon-Event": event_type,
        }
        if self.secret:
            headers["X-Decepticon-Signature"] = "sha256=" + _sign(self.secret, body)

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            # attempt 0 + 3 retries == 4 total, matching PSA (delays 0,1,2,4)
            for attempt, delay in enumerate((0.0, *_BACKOFFS)):
                if delay:
                    await asyncio.sleep(delay)
                try:
                    r = await client.post(self.url, content=body, headers=headers)
                    if 200 <= r.status_code < 300:
                        log.info(
                            "webhook.delivered",
                            extra={"url": self.url, "event": event_type, "attempt": attempt + 1},
                        )
                        return True
                    log.warning(
                        "webhook.http_error",
                        extra={"url": self.url, "status": r.status_code, "attempt": attempt + 1},
                    )
                except httpx.HTTPError as e:
                    log.warning(
                        "webhook.xport_error",
                        extra={"url": self.url, "err": str(e), "attempt": attempt + 1},
                    )
            log.error("webhook.exhausted", extra={"url": self.url, "event": event_type})
            return False


__all__ = ["WebhookDeliverer"]
