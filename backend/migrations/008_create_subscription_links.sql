-- migrations/008_create_subscription_links.sql
-- Links a store subscription purchase (Apple originalTransactionId, or
-- Google purchaseToken) to an internal user, and tracks its current
-- status. This is the missing piece flagged when the client-side paywall
-- was built: StoreKit 2 / Play Billing entitlement checks only gate the
-- app UI — the backend had no way to know a user's subscription status
-- at all. This table is what App Store Server Notifications / Google
-- Play RTDN webhooks update, and what auth enforcement checks against.

BEGIN;

CREATE TABLE IF NOT EXISTS subscription_links (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES users(id),
    platform           TEXT NOT NULL,              -- 'apple' | 'google'
    transaction_id     TEXT NOT NULL,               -- originalTransactionId (Apple) or purchaseToken (Google)
    product_id         TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'active',  -- active | expired | cancelled | grace_period | on_hold | billing_retry
    expires_at         TIMESTAMPTZ,
    auto_renew_status  BOOLEAN NOT NULL DEFAULT true,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A given store transaction/purchase token is unique across the whole
-- system (it identifies one specific purchase on Apple's or Google's
-- side) — this is what webhook updates key off of.
CREATE UNIQUE INDEX IF NOT EXISTS idx_subscription_links_transaction
    ON subscription_links (platform, transaction_id);

-- One active subscription record per user — a second purchase by the
-- same user (e.g. after cancelling and resubscribing) updates the
-- existing row rather than creating a duplicate.
CREATE UNIQUE INDEX IF NOT EXISTS idx_subscription_links_user
    ON subscription_links (user_id);

COMMIT;
