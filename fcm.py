"""Firebase Cloud Messaging integration."""
from __future__ import annotations

import json
import logging
import os

import firebase_admin
from firebase_admin import credentials, messaging

logger = logging.getLogger(__name__)

_app: firebase_admin.App | None = None


def init_firebase() -> None:
    """Initialize Firebase Admin SDK from environment."""
    global _app
    if _app is not None:
        return

    sa_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON", "")
    if not sa_json:
        raise RuntimeError("FIREBASE_SERVICE_ACCOUNT_JSON not set")

    # Support both inline JSON and file path
    if sa_json.strip().startswith("{"):
        cred = credentials.Certificate(json.loads(sa_json))
    else:
        cred = credentials.Certificate(sa_json)

    _app = firebase_admin.initialize_app(cred)
    logger.info("Firebase Admin SDK initialized (project: %s)", _app.project_id)


def send_push(
    fcm_token: str,
    title: str,
    body: str,
    encrypted_data: str | None = None,
) -> str | None:
    """Send a push notification via FCM.

    Args:
        fcm_token: Device FCM registration token
        title: Notification title (visible to Google/Apple)
        body: Notification body (visible to Google/Apple)
        encrypted_data: Base64-encoded encrypted payload (opaque to relay)

    Returns:
        FCM message ID on success, None on failure
    """
    data: dict[str, str] = {}
    if encrypted_data:
        data["encrypted"] = encrypted_data

    message = messaging.Message(
        token=fcm_token,
        notification=messaging.Notification(
            title=title,
            body=body,
        ),
        data=data,
        android=messaging.AndroidConfig(
            priority="high",
            notification=messaging.AndroidNotification(
                channel_id="frigate_alerts",
                default_sound=True,
                default_vibrate_timings=True,
            ),
        ),
        apns=messaging.APNSConfig(
            payload=messaging.APNSPayload(
                aps=messaging.Aps(
                    alert=messaging.ApsAlert(title=title, body=body),
                    sound="default",
                    mutable_content=True,
                ),
            ),
        ),
    )

    try:
        result = messaging.send(message)
        return result
    except messaging.UnregisteredError:
        logger.warning("FCM token unregistered: %s...", fcm_token[:20])
        return None
    except Exception as e:
        logger.error("FCM send failed: %s", e)
        return None


def send_test_push(fcm_token: str) -> str | None:
    """Send a test notification."""
    return send_push(
        fcm_token=fcm_token,
        title="Test Notification",
        body="Push relay is working!",
    )
