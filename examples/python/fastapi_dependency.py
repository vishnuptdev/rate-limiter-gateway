"""FastAPI dependency that asks RateGuard's check API for a decision.

Install:   pip install fastapi httpx

Usage:
    from fastapi import Depends, FastAPI
    from fastapi_dependency import rate_limit

    app = FastAPI()

    @app.get("/v1/orders", dependencies=[Depends(rate_limit)])
    async def orders():
        ...

Environment:
    RATEGUARD_URL     base URL of RateGuard's data plane, e.g. http://rateguard:8080
    RATEGUARD_TOKEN   API token with scope "check" (rgt_...)

Behaviour:
- Allowed: RateLimit-* headers are added to the response and the handler runs.
- Denied: HTTP 429 with Retry-After and the decision details.
- Fail-open: if RateGuard errors or does not answer within 50 ms, the request
  continues. A bad token also fails open, so watch the warnings in your logs.

The consumer's API key is read from the X-API-Key header and sent in the check
body as "api_key". Behind a load balancer, make sure the proxy address is in
RateGuard's trusted proxies, or pass the real client IP through.
"""

import logging
import os
from typing import Any

import httpx
from fastapi import HTTPException, Request, Response

log = logging.getLogger("rateguard")

RATEGUARD_URL = os.environ.get("RATEGUARD_URL", "http://localhost:8080").rstrip("/")
RATEGUARD_TOKEN = os.environ.get("RATEGUARD_TOKEN", "")
CHECK_TIMEOUT_S = 0.05  # 50 ms; beyond this the request fails open

# One client per process, reused across requests. Close it on application shutdown
# if you need a clean exit: await _client.aclose()
_client = httpx.AsyncClient(timeout=CHECK_TIMEOUT_S)


async def rate_limit(request: Request, response: Response) -> None:
    body: dict[str, Any] = {
        "method": request.method,
        "path": request.url.path,
        "host": request.url.hostname or "",
        "api_key": request.headers.get("x-api-key"),
        "ip": request.client.host if request.client else None,
        "cost": 1,
    }
    body = {k: v for k, v in body.items() if v is not None}

    try:
        r = await _client.post(
            f"{RATEGUARD_URL}/_rlg/v1/check",
            json=body,
            headers={"Authorization": f"Bearer {RATEGUARD_TOKEN}"},
        )
        r.raise_for_status()
        decision = r.json()
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("rateguard: check failed, failing open: %s", exc)
        return

    headers = {str(k): str(v) for k, v in (decision.get("headers") or {}).items()}

    if decision.get("allowed", True) is False:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limited",
                "message": "Rate limit exceeded",
                "policy": decision.get("policy_id"),
                "limit": decision.get("limit"),
                "remaining": decision.get("remaining"),
                "retry_after_s": decision.get("retry_after_s"),
                "reset_s": decision.get("reset_s"),
            },
            headers=headers,
        )

    for name, value in headers.items():
        response.headers[name] = value
