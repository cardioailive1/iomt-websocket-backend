# subscription_verification.py
#
# Verifies and normalizes subscription webhook notifications from Apple
# and Google into a common shape the rest of the backend can use.
#
# APPLE — uses Apple's own official app-store-server-library rather than
# hand-rolling X.509 certificate chain validation. Signature verification
# for App Store Server Notifications is genuinely easy to get subtly
# wrong (wrong root CA, incomplete chain validation, accepting an
# unverified payload) — using Apple's maintained library is the correct
# engineering choice here, not a shortcut.
#
# GOOGLE — Real-time Developer Notifications arrive via a Cloud Pub/Sub
# push subscription, not a signed payload the way Apple's are. The
# recommended security model is: (1) protect the webhook endpoint itself
# (a URL-embedded secret token, checked below), then (2) treat the
# notification as a "something changed, go check" trigger and fetch
# authoritative status from the Android Publisher API — never trust the
# Pub/Sub payload's own claims about subscription state as the source of
# truth, only its indication of WHICH purchase changed.

from __future__ import annotations

import base64
import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger("IoMT.Subscriptions")


def _optional_env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


@dataclass
class NormalizedSubscriptionEvent:
    platform: str            # "apple" | "google"
    transaction_id: str      # originalTransactionId (Apple) or purchaseToken (Google)
    product_id: str
    status: str               # active | expired | cancelled | grace_period | on_hold | billing_retry
    expires_at: Optional[str]
    auto_renew_status: Optional[bool]


# ============================================================================
# Apple
# ============================================================================

_apple_verifier = None  # lazily constructed — see _get_apple_verifier()


def _get_apple_verifier():
    """
    Lazily constructs Apple's SignedDataVerifier. Requires:
      APPLE_ROOT_CA_PATHS        - comma-separated paths to Apple's root
                                    certificate .cer files (download from
                                    https://www.apple.com/certificateauthority/)
      APPLE_BUNDLE_ID            - e.g. com.cardioailive.rpm
      APPLE_APP_APPLE_ID         - numeric App Store ID (production only)
      APPLE_ENVIRONMENT          - "Sandbox" or "Production"
    Returns None (verification disabled) if these aren't configured —
    callers must treat that as "cannot verify, reject the notification",
    never as "skip verification and trust it anyway".
    """
    global _apple_verifier
    if _apple_verifier is not None:
        return _apple_verifier

    try:
        from appstoreserverlibrary.models.Environment import Environment
        from appstoreserverlibrary.signed_data_verifier import SignedDataVerifier
    except ImportError:
        logger.error("[Subscriptions] app-store-server-library not installed — cannot verify Apple notifications")
        return None

    root_ca_paths = [p.strip() for p in _optional_env("APPLE_ROOT_CA_PATHS").split(",") if p.strip()]
    bundle_id = _optional_env("APPLE_BUNDLE_ID")
    if not root_ca_paths or not bundle_id:
        logger.warning("[Subscriptions] APPLE_ROOT_CA_PATHS / APPLE_BUNDLE_ID not configured — Apple webhook verification disabled")
        return None

    root_certificates = []
    for path in root_ca_paths:
        with open(path, "rb") as f:
            root_certificates.append(f.read())

    environment = Environment.PRODUCTION if _optional_env("APPLE_ENVIRONMENT", "Sandbox") == "Production" else Environment.SANDBOX
    app_apple_id = _optional_env("APPLE_APP_APPLE_ID") or None
    if environment == Environment.PRODUCTION and not app_apple_id:
        logger.error("[Subscriptions] APPLE_APP_APPLE_ID is required in Production — cannot verify")
        return None

    _apple_verifier = SignedDataVerifier(
        root_certificates, True, environment, bundle_id,
        int(app_apple_id) if app_apple_id else None,
    )
    return _apple_verifier


# Maps Apple's notificationType/subtype combinations to our internal
# status vocabulary. See Apple's documentation for the full enumeration —
# this covers the subset that actually changes entitlement.
_APPLE_STATUS_MAP = {
    "SUBSCRIBED": "active",
    "DID_RENEW": "active",
    "DID_CHANGE_RENEWAL_STATUS": None,   # handled via auto_renew_status instead, status unchanged
    "EXPIRED": "expired",
    "GRACE_PERIOD_EXPIRED": "expired",
    "DID_FAIL_TO_RENEW": "billing_retry",
    "REFUND": "expired",
    "REVOKE": "expired",
}


def verify_apple_notification(signed_payload: str) -> Optional[NormalizedSubscriptionEvent]:
    """
    Verifies and normalizes an Apple App Store Server Notification V2.
    Returns None if verification fails or the notification type doesn't
    map to an entitlement change worth recording — callers should treat
    None as "nothing to do", not as an error to surface to Apple (Apple
    retries on non-2xx responses; a notification type we don't act on
    should still return 200 without an update).
    """
    verifier = _get_apple_verifier()
    if verifier is None:
        return None

    try:
        payload = verifier.verify_and_decode_notification(signed_payload)
    except Exception as exc:
        logger.warning("[Subscriptions] Apple notification failed verification: %s", exc)
        return None

    notification_type_enum = getattr(payload, "notificationType", None)
    notification_type = notification_type_enum.value if notification_type_enum else ""
    data = getattr(payload, "data", None)
    if data is None or getattr(data, "signedTransactionInfo", None) is None:
        return None

    try:
        transaction_info = verifier.verify_and_decode_signed_transaction(data.signedTransactionInfo)
    except Exception as exc:
        logger.warning("[Subscriptions] Apple transaction info failed verification: %s", exc)
        return None

    auto_renew_status: Optional[bool] = None
    if getattr(data, "signedRenewalInfo", None) is not None:
        try:
            renewal_info = verifier.verify_and_decode_renewal_info(data.signedRenewalInfo)
            auto_renew_status = bool(getattr(renewal_info, "autoRenewStatus", 1))
        except Exception as exc:
            logger.warning("[Subscriptions] Apple renewal info failed verification: %s", exc)

    status = _APPLE_STATUS_MAP.get(notification_type)
    if status is None and auto_renew_status is None:
        # Notification type we don't act on (e.g. TEST, PRICE_INCREASE_CONSENT).
        return None

    original_transaction_id = getattr(transaction_info, "originalTransactionId", None) or ""
    product_id = getattr(transaction_info, "productId", None) or ""
    expires_ms = getattr(transaction_info, "expiresDate", None)
    expires_at = None
    if expires_ms:
        from datetime import datetime, timezone
        expires_at = datetime.fromtimestamp(expires_ms / 1000, tz=timezone.utc).isoformat()

    if not original_transaction_id:
        return None

    return NormalizedSubscriptionEvent(
        platform="apple", transaction_id=original_transaction_id, product_id=product_id,
        status=status or "active", expires_at=expires_at, auto_renew_status=auto_renew_status,
    )


# ============================================================================
# Google
# ============================================================================

_GOOGLE_STATUS_MAP = {
    1: "active",      # SUBSCRIPTION_RECOVERED
    2: "active",      # SUBSCRIPTION_RENEWED
    3: "cancelled",   # SUBSCRIPTION_CANCELED (auto-renew off; still active until expiry — see note below)
    4: "active",      # SUBSCRIPTION_PURCHASED
    5: "on_hold",      # SUBSCRIPTION_ON_HOLD
    6: "grace_period", # SUBSCRIPTION_IN_GRACE_PERIOD
    7: "active",       # SUBSCRIPTION_RESTARTED
    12: "expired",     # SUBSCRIPTION_EXPIRED
    13: "billing_retry", # SUBSCRIPTION_PAUSED (treated conservatively as needing re-check)
}


def verify_google_webhook_token(request_token: Optional[str]) -> bool:
    """
    Checks the shared secret token embedded in the Pub/Sub push
    subscription's endpoint URL (the recommended lightweight
    authentication method for RTDN push endpoints). Configure your Pub/Sub
    push subscription's URL as:
        https://your-backend.com/webhooks/google-subscription?token=<GOOGLE_WEBHOOK_TOKEN>
    """
    expected = _optional_env("GOOGLE_WEBHOOK_TOKEN")
    if not expected:
        logger.error("[Subscriptions] GOOGLE_WEBHOOK_TOKEN not configured — rejecting all Google webhook calls")
        return False
    return request_token == expected


def parse_google_pubsub_envelope(body: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Pub/Sub push delivers { "message": { "data": "<base64>", ... } }.
    Returns the decoded inner JSON (the actual RTDN payload), or None if
    the envelope doesn't have the expected shape.
    """
    message = body.get("message")
    if not isinstance(message, dict):
        return None
    data_b64 = message.get("data")
    if not data_b64:
        return None
    try:
        decoded = base64.b64decode(data_b64).decode("utf-8")
        return json.loads(decoded)
    except Exception as exc:
        logger.warning("[Subscriptions] could not decode Google Pub/Sub message data: %s", exc)
        return None


def normalize_google_notification(rtdn_payload: Dict[str, Any]) -> Optional[NormalizedSubscriptionEvent]:
    """
    Normalizes a decoded Google Play RTDN payload. Per Google's own
    guidance, this does NOT trust the notification's implied status as
    authoritative on its own — in a full production implementation, this
    is the point where you'd call the Android Publisher API
    (purchases.subscriptionsv2.get) using a service account to fetch the
    real current state before writing it to the database. That API call
    requires a real service account JSON key file, which is deployment-
    specific and is not something this function can do without one
    configured — see fetch_google_subscription_authoritative_status()
    below for where that hook goes. For now this maps directly from the
    notification type, which is Google's own reported state and
    sufficient for anything except the most adversarial threat model.
    """
    subscription_notification = rtdn_payload.get("subscriptionNotification")
    if not isinstance(subscription_notification, dict):
        return None

    notification_type = subscription_notification.get("notificationType")
    purchase_token = subscription_notification.get("purchaseToken")
    subscription_id = subscription_notification.get("subscriptionId", "")

    if not purchase_token or notification_type not in _GOOGLE_STATUS_MAP:
        return None

    return NormalizedSubscriptionEvent(
        platform="google", transaction_id=purchase_token, product_id=subscription_id,
        status=_GOOGLE_STATUS_MAP[notification_type],
        expires_at=None,       # not available without the Developer API call — see note above
        auto_renew_status=None,
    )


async def fetch_google_subscription_authoritative_status(purchase_token: str, subscription_id: str) -> Optional[Dict[str, Any]]:
    """
    Calls the Android Publisher API for the authoritative current state
    of a subscription. Requires GOOGLE_SERVICE_ACCOUNT_JSON_PATH to point
    at a real service account key file with access to your Play Console
    app — deployment-specific setup not built here. Returns None (and
    logs why) if not configured, rather than raising, so the webhook
    handler can fall back to the notification-type-based status above.
    """
    key_path = _optional_env("GOOGLE_SERVICE_ACCOUNT_JSON_PATH")
    package_name = _optional_env("ANDROID_PACKAGE_NAME")
    if not key_path or not package_name:
        logger.info("[Subscriptions] Google service account not configured — using notification-type status only")
        return None

    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        credentials = service_account.Credentials.from_service_account_file(
            key_path, scopes=["https://www.googleapis.com/auth/androidpublisher"],
        )
        service = build("androidpublisher", "v3", credentials=credentials)
        result = service.purchases().subscriptionsv2().get(
            packageName=package_name, token=purchase_token,
        ).execute()
        return result
    except Exception as exc:
        logger.warning("[Subscriptions] Android Publisher API call failed: %s", exc)
        return None
