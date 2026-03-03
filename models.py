"""Data models for the push relay server."""
from __future__ import annotations

from datetime import datetime, timezone
from pydantic import BaseModel, Field


# ── Request Models ──────────────────────────────────────────────

class RegisterBridgeRequest(BaseModel):
    """Bridge registration request."""
    pass  # No fields needed; returns bridge_id + bridge_secret


class RegisterDeviceRequest(BaseModel):
    """Device registration request (called by bridge on behalf of device)."""
    fcm_token: str
    platform: str = "unknown"  # "ios" or "android"


class PushRequest(BaseModel):
    """Push notification request from bridge."""
    device_ids: list[str]
    payload: str  # Base64-encoded encrypted notification payload
    title: str = "Frigate Alert"
    body: str = "New event detected"


class PushTestRequest(BaseModel):
    """Test push notification request."""
    device_ids: list[str]


# ── Response Models ─────────────────────────────────────────────

class RegisterBridgeResponse(BaseModel):
    bridge_id: str
    bridge_secret: str


class RegisterDeviceResponse(BaseModel):
    device_id: str


class PushResponse(BaseModel):
    success: bool
    sent: int = 0
    failed: int = 0
    errors: list[str] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"


# ── Storage Models ──────────────────────────────────────────────

class Bridge(BaseModel):
    bridge_id: str
    bridge_secret_hash: str
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_push_at: datetime | None = None
    push_count_today: int = 0
    push_count_date: str = ""  # YYYY-MM-DD for daily reset


class Device(BaseModel):
    device_id: str
    bridge_id: str
    fcm_token: str
    platform: str = "unknown"
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    push_count_today: int = 0
    push_count_date: str = ""
