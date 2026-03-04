# Frigate Push Relay (Firebase Cloud Functions)

Production relay for FrigateMobile push notifications with client-side E2E encryption preserved.

## Endpoints

- `registerToken` (app-side)
  - Verifies Firebase Auth ID token (`Authorization: Bearer <idToken>`)
  - Verifies Firebase App Check token (`X-Firebase-AppCheck`)
  - Stores `(bridgeId/deviceId -> fcmToken)` and bridge auth token hash
  - Rejects any E2E key material fields
- `sendNotification` (bridge-side)
  - Verifies bridge auth token (`Authorization: Bearer <bridgeAuthToken>`)
  - Enforces strict CORS (`home-assistant.io` + local network origins)
  - Rate limits to `100 notifications/minute/bridge` (configurable)
  - Enforces encrypted payload max size of `4KB`
  - Forwards payload to FCM only (no decrypt, no key storage)

## Firestore Schema

- `bridgeRegistrations/{bridgeId}`
  - `userId`, `bridgeTokenHash`, `createdAt`, `updatedAt`, `lastUsedAt`, `expiresAt`
  - `expiresAt` is TTL-enabled to remove stale bridge registrations
- `bridgeRegistrations/{bridgeId}/devices/{deviceId}`
  - `fcmToken`, `platform`, `appVersion`, `appId`, `lastNotifiedAt`, `expiresAt`
  - `expiresAt` is TTL-enabled to remove stale device tokens
- `bridgeRateLimits/{bridgeId_yyyyMMddHHmm}`
  - `count`, `minuteKey`, `updatedAt`, `expiresAt`
  - Used for per-bridge minute rate limiting
- `bridgeUsageDaily/{yyyyMMdd_bridgeId}`
  - `requests`, `sent`, `failed`, `bytesForwarded`, `updatedAt`, `expiresAt`
  - Used for per-user/per-bridge usage tracking and future billing

## Security Guardrails

- App requests require both Firebase Auth + App Check
- Bridge requests require per-bridge auth token hash validation
- Server never decrypts payloads and never stores encryption keys
- Secrets are loaded from Google Secret Manager (`TOKEN_HASH_PEPPER`)
- FCM delivery retries use exponential backoff with max `3` retries

## Configuration

Copy `functions/.env.example` to `functions/.env` for local emulation values.

Required Secret Manager secret:

- `TOKEN_HASH_PEPPER`

Create/update it:

```bash
echo -n "replace-with-long-random-secret" | firebase functions:secrets:set TOKEN_HASH_PEPPER
```

## Deploy

```bash
cd functions
npm install
npm run lint
npm run build
cd ..
firebase deploy --only functions,firestore
```

## Enable Firestore TTL

Enable TTL policy on `expiresAt` for these collection groups:

- `bridgeRegistrations`
- `devices`
- `bridgeRateLimits`
- `bridgeUsageDaily`

Example:

```bash
gcloud firestore fields ttls update expiresAt --collection-group=devices --enable-ttl
```

Run once per collection group.

## Budget Alerts (Firebase/GCP Billing)

Create budget with thresholds and email/PubSub alerts:

1. Google Cloud Console -> Billing -> Budgets & alerts
2. Create budget for Firebase project billing account
3. Set threshold alerts at `50%`, `75%`, `90%`, `100%`
4. Add alert recipients (on-call email) and optional Pub/Sub topic
5. Configure incident notifications in Cloud Monitoring

CLI option:

```bash
gcloud billing budgets create \
  --billing-account=YOUR_BILLING_ACCOUNT_ID \
  --display-name="Frigate Relay Monthly Budget" \
  --budget-amount=20USD \
  --threshold-rule=percent=0.5 \
  --threshold-rule=percent=0.75 \
  --threshold-rule=percent=0.9 \
  --threshold-rule=percent=1.0
```

## Request Examples

`registerToken`:

```json
{
  "bridgeId": "bridge-alpha",
  "deviceId": "iphone-15",
  "bridgeAuthToken": "bridge-token-from-pairing",
  "fcmToken": "fcm-registration-token",
  "platform": "ios",
  "appVersion": "1.5.0"
}
```

`sendNotification`:

```json
{
  "bridgeId": "bridge-alpha",
  "deviceIds": ["iphone-15"],
  "encryptedPayload": "base64-or-json-ciphertext",
  "title": "Frigate Alert",
  "body": "Motion detected"
}
```
