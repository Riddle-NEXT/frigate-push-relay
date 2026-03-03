"""Frigate Push Relay Server.

A minimal push notification relay that forwards encrypted notification payloads
from Frigate Notify Bridge instances to mobile devices via FCM.
The relay never sees notification content — only encrypted blobs.
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
from datetime import datetime, timezone

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException

from fcm import init_firebase, send_push, send_test_push
from models import (
    Bridge,
    Device,
    HealthResponse,
    PushRequest,
    PushResponse,
    PushTestRequest,
    RegisterBridgeRequest,
    RegisterBridgeResponse,
    RegisterDeviceRequest,
    RegisterDeviceResponse,
)

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

RATE_LIMIT = int(os.environ.get("RATE_LIMIT_PER_DEVICE_PER_DAY", "500"))

app = FastAPI(
    title="Frigate Push Relay",
    version="0.1.0",
    description="Push notification relay for Frigate Mobile — no notification content stored.",
)

# ── In-memory storage (swap for Redis/DB in production) ────────

bridges: dict[str, Bridge] = {}
devices: dict[str, Device] = {}  # device_id → Device
# Reverse index: bridge_id → set of device_ids
bridge_devices: dict[str, set[str]] = {}


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# ── Auth dependency ─────────────────────────────────────────────

def _verify_bridge(authorization: str = Header(...)) -> Bridge:
    """Verify bridge_secret from Authorization header."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing Bearer token")
    secret = authorization[7:]
    hashed = _hash_secret(secret)

    for bridge in bridges.values():
        if bridge.bridge_secret_hash == hashed:
            return bridge
    raise HTTPException(401, "Invalid bridge secret")


# ── Startup ─────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    init_firebase()
    logger.info("Frigate Push Relay started (rate limit: %d/device/day)", RATE_LIMIT)


# ── Endpoints ───────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse()


@app.post("/register/bridge", response_model=RegisterBridgeResponse)
async def register_bridge(_: RegisterBridgeRequest = None):
    """Register a new bridge instance. Returns bridge_id + bridge_secret."""
    bridge_id = secrets.token_urlsafe(16)
    bridge_secret = secrets.token_urlsafe(32)

    bridges[bridge_id] = Bridge(
        bridge_id=bridge_id,
        bridge_secret_hash=_hash_secret(bridge_secret),
    )
    bridge_devices[bridge_id] = set()

    logger.info("Bridge registered: %s", bridge_id)
    return RegisterBridgeResponse(bridge_id=bridge_id, bridge_secret=bridge_secret)


@app.post("/register/device", response_model=RegisterDeviceResponse)
async def register_device(
    req: RegisterDeviceRequest,
    bridge: Bridge = Depends(_verify_bridge),
):
    """Register a device's FCM token, linked to a bridge."""
    device_id = secrets.token_urlsafe(16)

    devices[device_id] = Device(
        device_id=device_id,
        bridge_id=bridge.bridge_id,
        fcm_token=req.fcm_token,
        platform=req.platform,
    )
    bridge_devices.setdefault(bridge.bridge_id, set()).add(device_id)

    logger.info("Device registered: %s (bridge: %s)", device_id, bridge.bridge_id)
    return RegisterDeviceResponse(device_id=device_id)


@app.delete("/device/{device_id}")
async def unregister_device(
    device_id: str,
    bridge: Bridge = Depends(_verify_bridge),
):
    """Unregister a device."""
    device = devices.get(device_id)
    if not device or device.bridge_id != bridge.bridge_id:
        raise HTTPException(404, "Device not found")

    devices.pop(device_id, None)
    bridge_devices.get(bridge.bridge_id, set()).discard(device_id)

    logger.info("Device unregistered: %s", device_id)
    return {"success": True}


@app.post("/push", response_model=PushResponse)
async def push(
    req: PushRequest,
    bridge: Bridge = Depends(_verify_bridge),
):
    """Send encrypted notification to device(s)."""
    today = _today()
    sent = 0
    failed = 0
    errors: list[str] = []

    for did in req.device_ids:
        device = devices.get(did)
        if not device or device.bridge_id != bridge.bridge_id:
            errors.append(f"{did}: not found or not owned")
            failed += 1
            continue

        # Rate limiting
        if device.push_count_date != today:
            device.push_count_today = 0
            device.push_count_date = today
        if device.push_count_today >= RATE_LIMIT:
            errors.append(f"{did}: rate limit exceeded")
            failed += 1
            continue

        result = send_push(
            fcm_token=device.fcm_token,
            title=req.title,
            body=req.body,
            encrypted_data=req.payload,
        )

        if result:
            device.push_count_today += 1
            sent += 1
        else:
            errors.append(f"{did}: FCM send failed")
            failed += 1

    # Update bridge stats
    bridge.last_push_at = datetime.now(timezone.utc)
    if bridge.push_count_date != today:
        bridge.push_count_today = 0
        bridge.push_count_date = today
    bridge.push_count_today += sent

    return PushResponse(success=failed == 0, sent=sent, failed=failed, errors=errors)


@app.post("/push/test", response_model=PushResponse)
async def push_test(
    req: PushTestRequest,
    bridge: Bridge = Depends(_verify_bridge),
):
    """Send a test notification to device(s)."""
    sent = 0
    failed = 0
    errors: list[str] = []

    for did in req.device_ids:
        device = devices.get(did)
        if not device or device.bridge_id != bridge.bridge_id:
            errors.append(f"{did}: not found")
            failed += 1
            continue

        result = send_test_push(device.fcm_token)
        if result:
            sent += 1
        else:
            errors.append(f"{did}: send failed")
            failed += 1

    return PushResponse(success=failed == 0, sent=sent, failed=failed, errors=errors)


if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("main:app", host=host, port=port, reload=True)
