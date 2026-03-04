import {initializeApp} from "firebase-admin/app";
import {getAppCheck} from "firebase-admin/app-check";
import {getAuth} from "firebase-admin/auth";
import {FieldValue, Timestamp, getFirestore} from "firebase-admin/firestore";
import {Message} from "firebase-admin/messaging";
import {Response} from "express";
import {logger} from "firebase-functions";
import {onRequest, Request} from "firebase-functions/v2/https";
import {defineInt, defineSecret, defineString} from "firebase-functions/params";
import {
  addDays,
  getDateKey,
  getMinuteKey,
  hasForbiddenE2EFields,
  hashToken,
  readBearerToken,
  validateBridgeOrigin,
} from "./auth";
import {sendPushWithRetry} from "./fcm";
import {
  BridgeRegistrationDoc,
  DeviceRegistrationDoc,
  RegisterTokenRequest,
  SendNotificationRequest,
} from "./types";

initializeApp();


const TOKEN_HASH_PEPPER = defineSecret("TOKEN_HASH_PEPPER");
const GOOGLE_CLIENT_SECRET_PARAM = defineSecret("GOOGLE_CLIENT_SECRET");
const GOOGLE_CLIENT_ID_PARAM = defineString("GOOGLE_CLIENT_ID", {
  default: "REDACTED_GOOGLE_CLIENT_ID",
});
const RATE_LIMIT_PER_MINUTE = defineInt("RATE_LIMIT_PER_MINUTE", {default: 100});
const TOKEN_TTL_DAYS = defineInt("TOKEN_TTL_DAYS", {default: 30});
const USAGE_TTL_DAYS = defineInt("USAGE_TTL_DAYS", {default: 120});
const MAX_BATCH_DEVICES = defineInt("MAX_BATCH_DEVICES", {default: 20});
const BRIDGE_ALLOWED_ORIGINS = defineString("BRIDGE_ALLOWED_ORIGINS", {
  default: "https://home-assistant.io,https://www.home-assistant.io",
});

const OPTIONS = {
  region: "us-central1",
  memory: "256MiB" as const,
  timeoutSeconds: 30,
  secrets: [TOKEN_HASH_PEPPER],
};

/**
 * health returns a simple 200 OK for relay reachability checks.
 */
export const health = onRequest({...OPTIONS, secrets: []}, async (_req, res) => {
  res.status(200).json({status: "ok", service: "frigate-push-relay"});
});

function parseRegisterTokenBody(body: unknown): RegisterTokenRequest {
  if (!body || typeof body !== "object") {
    throw new Error("Request body must be a JSON object");
  }

  const payload = body as Record<string, unknown>;
  if (hasForbiddenE2EFields(payload)) {
    throw new Error("Relay does not accept E2E key material");
  }

  const bridgeId = String(payload.bridgeId ?? "").trim();
  const deviceId = String(payload.deviceId ?? "").trim();
  const bridgeAuthToken = String(payload.bridgeAuthToken ?? "").trim();
  const fcmToken = String(payload.fcmToken ?? "").trim();
  const platform = String(payload.platform ?? "unknown").trim().toLowerCase();
  const appVersion = payload.appVersion ? String(payload.appVersion).trim() : undefined;

  if (!/^[A-Za-z0-9._:-]{3,128}$/.test(bridgeId)) {
    throw new Error("bridgeId is invalid");
  }
  if (!/^[A-Za-z0-9._:-]{3,128}$/.test(deviceId)) {
    throw new Error("deviceId is invalid");
  }
  if (bridgeAuthToken.length < 24 || bridgeAuthToken.length > 512) {
    throw new Error("bridgeAuthToken must be between 24 and 512 characters");
  }
  if (fcmToken.length < 24 || fcmToken.length > 4096) {
    throw new Error("fcmToken is invalid");
  }
  if (!["ios", "android", "unknown"].includes(platform)) {
    throw new Error("platform must be ios, android, or unknown");
  }
  if (appVersion && appVersion.length > 64) {
    throw new Error("appVersion is too long");
  }

  return {
    bridgeId,
    deviceId,
    bridgeAuthToken,
    fcmToken,
    platform: platform as "ios" | "android" | "unknown",
    appVersion,
  };
}

function parseSendNotificationBody(body: unknown): SendNotificationRequest {
  if (!body || typeof body !== "object") {
    throw new Error("Request body must be a JSON object");
  }

  const payload = body as Record<string, unknown>;
  if (hasForbiddenE2EFields(payload)) {
    throw new Error("Relay does not process E2E keys");
  }

  const bridgeId = String(payload.bridgeId ?? "").trim();
  const encryptedPayload = String(payload.encryptedPayload ?? "");
  const title = payload.title ? String(payload.title) : undefined;
  const msgBody = payload.body ? String(payload.body) : undefined;
  const singleDeviceId = payload.deviceId ? String(payload.deviceId).trim() : undefined;
  const listDeviceIds = Array.isArray(payload.deviceIds) ? payload.deviceIds : [];

  if (!/^[A-Za-z0-9._:-]{3,128}$/.test(bridgeId)) {
    throw new Error("bridgeId is invalid");
  }
  if (!encryptedPayload) {
    throw new Error("encryptedPayload is required");
  }

  const payloadBytes = Buffer.byteLength(encryptedPayload, "utf8");
  if (payloadBytes > 4096) {
    throw new Error("encryptedPayload exceeds 4KB limit");
  }
  if (title && title.length > 120) {
    throw new Error("title is too long");
  }
  if (msgBody && msgBody.length > 500) {
    throw new Error("body is too long");
  }

  const deviceIds = new Set<string>();
  if (singleDeviceId) {
    deviceIds.add(singleDeviceId);
  }
  for (const raw of listDeviceIds) {
    if (typeof raw === "string") {
      const parsed = raw.trim();
      if (parsed) {
        deviceIds.add(parsed);
      }
    }
  }

  if (deviceIds.size === 0) {
    throw new Error("At least one target deviceId is required");
  }

  for (const deviceId of deviceIds) {
    if (!/^[A-Za-z0-9._:-]{3,128}$/.test(deviceId)) {
      throw new Error("deviceId is invalid");
    }
  }

  return {
    bridgeId,
    encryptedPayload,
    title,
    body: msgBody,
    deviceIds: [...deviceIds],
  };
}

async function verifyAppIdentity(req: Request): Promise<{uid: string; appId: string}> {
  const authHeader = req.get("authorization");
  const appCheckHeader = req.get("X-Firebase-AppCheck");

  if (!appCheckHeader) {
    throw new Error("Missing App Check token");
  }

  const idToken = readBearerToken(authHeader);
  const [decodedAuthToken, decodedAppCheckToken] = await Promise.all([
    getAuth().verifyIdToken(idToken, true),
    getAppCheck().verifyToken(appCheckHeader),
  ]);

  return {
    uid: decodedAuthToken.uid,
    appId: decodedAppCheckToken.appId,
  };
}

async function enforceBridgeRateLimit(
  bridgeId: string,
  notificationsRequested: number,
  now: Date
): Promise<void> {
  const db = getFirestore();
  const minuteKey = getMinuteKey(now);
  const rateLimitRef = db.collection("bridgeRateLimits").doc(`${bridgeId}_${minuteKey}`);
  const expiresAt = Timestamp.fromDate(addDays(now, 1));

  await db.runTransaction(async (transaction) => {
    const snapshot = await transaction.get(rateLimitRef);
    const existingCount = snapshot.exists ? Number(snapshot.data()?.count ?? 0) : 0;
    const nextCount = existingCount + notificationsRequested;

    if (nextCount > RATE_LIMIT_PER_MINUTE.value()) {
      throw new Error("Rate limit exceeded");
    }

    transaction.set(
      rateLimitRef,
      {
        bridgeId,
        minuteKey,
        count: nextCount,
        updatedAt: FieldValue.serverTimestamp(),
        expiresAt,
      },
      {merge: true}
    );
  });
}

function writeCorsHeaders(res: Response, origin: string | undefined): void {
  if (!origin) {
    return;
  }
  res.set("Access-Control-Allow-Origin", origin);
  res.set("Vary", "Origin");
  res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
  res.set("Access-Control-Max-Age", "3600");
}

async function updateUsageCounters(
  bridgeId: string,
  userId: string,
  sent: number,
  failed: number,
  bytesForwarded: number,
  now: Date
): Promise<void> {
  const dateKey = getDateKey(now);
  const usageRef = getFirestore().collection("bridgeUsageDaily").doc(`${dateKey}_${bridgeId}`);
  const expiresAt = Timestamp.fromDate(addDays(now, USAGE_TTL_DAYS.value()));

  await usageRef.set(
    {
      bridgeId,
      userId,
      dateKey,
      requests: FieldValue.increment(1),
      sent: FieldValue.increment(sent),
      failed: FieldValue.increment(failed),
      bytesForwarded: FieldValue.increment(bytesForwarded),
      updatedAt: FieldValue.serverTimestamp(),
      expiresAt,
    },
    {merge: true}
  );
}

async function updateBridgeLastUsed(bridgeId: string): Promise<void> {
  const bridgeRef = getFirestore().collection("bridgeRegistrations").doc(bridgeId);
  await bridgeRef.set(
    {
      lastUsedAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
    },
    {merge: true}
  );
}

/**
 * registerToken validates app auth + App Check, then stores bridge/device to FCM mapping.
 */
export const registerToken = onRequest(OPTIONS, async (req, res) => {
  if (req.method !== "POST") {
    res.status(405).json({error: "Method not allowed"});
    return;
  }

  try {
    const identity = await verifyAppIdentity(req);
    const body = parseRegisterTokenBody(req.body);
    const now = new Date();
    const db = getFirestore();
    const pepper = TOKEN_HASH_PEPPER.value();
    const bridgeTokenHash = hashToken(body.bridgeAuthToken, pepper);
    const expiresAt = Timestamp.fromDate(addDays(now, TOKEN_TTL_DAYS.value()));
    const bridgeRef = db.collection("bridgeRegistrations").doc(body.bridgeId);
    const deviceRef = bridgeRef.collection("devices").doc(body.deviceId);

    await db.runTransaction(async (transaction) => {
      const bridgeSnapshot = await transaction.get(bridgeRef);

      if (bridgeSnapshot.exists) {
        const existing = bridgeSnapshot.data() as BridgeRegistrationDoc;
        if (existing.userId !== identity.uid) {
          throw new Error("bridgeId is already linked to another user");
        }
      }

      transaction.set(
        bridgeRef,
        {
          bridgeId: body.bridgeId,
          userId: identity.uid,
          bridgeTokenHash,
          createdAt: bridgeSnapshot.exists ? bridgeSnapshot.data()?.createdAt : Timestamp.now(),
          updatedAt: FieldValue.serverTimestamp(),
          lastUsedAt: bridgeSnapshot.exists ? bridgeSnapshot.data()?.lastUsedAt ?? null : null,
          expiresAt,
        },
        {merge: true}
      );

      transaction.set(
        deviceRef,
        {
          bridgeId: body.bridgeId,
          deviceId: body.deviceId,
          userId: identity.uid,
          appId: identity.appId,
          fcmToken: body.fcmToken,
          platform: body.platform,
          appVersion: body.appVersion ?? null,
          createdAt: FieldValue.serverTimestamp(),
          updatedAt: FieldValue.serverTimestamp(),
          lastNotifiedAt: null,
          expiresAt,
        },
        {merge: true}
      );
    });

    res.status(200).json({
      ok: true,
      bridgeId: body.bridgeId,
      deviceId: body.deviceId,
      expiresAt: expiresAt.toDate().toISOString(),
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    logger.error("registerToken failed", {
      reason: message,
      hasAuthHeader: Boolean(req.get("authorization")),
      hasAppCheckHeader: Boolean(req.get("X-Firebase-AppCheck")),
      ip: req.ip,
      userAgent: req.get("user-agent") ?? "unknown",
    });

    if (message.includes("App Check") || message.includes("Bearer") || message.includes("linked")) {
      res.status(401).json({error: message});
      return;
    }

    if (message.includes("invalid") || message.includes("required") || message.includes("4KB")) {
      res.status(400).json({error: message});
      return;
    }

    res.status(500).json({error: "Internal server error"});
  }
});

/**
 * sendNotification validates bridge auth, applies anti-abuse controls, and forwards encrypted payloads to FCM.
 */
export const sendNotification = onRequest(OPTIONS, async (req, res) => {
  const origin = req.get("origin");
  const allowedOrigins = new Set(
    BRIDGE_ALLOWED_ORIGINS.value()
      .split(",")
      .map((value) => value.trim())
      .filter((value) => value.length > 0)
  );

  if (!validateBridgeOrigin(req, allowedOrigins)) {
    res.status(403).json({error: "Origin not allowed"});
    return;
  }

  writeCorsHeaders(res, origin);

  if (req.method === "OPTIONS") {
    res.status(204).send();
    return;
  }

  if (req.method !== "POST") {
    res.status(405).json({error: "Method not allowed"});
    return;
  }

  const startedAt = new Date();

  try {
    const body = parseSendNotificationBody(req.body);
    if ((body.deviceIds?.length ?? 0) > MAX_BATCH_DEVICES.value()) {
      res.status(400).json({error: `deviceIds exceeds max batch size of ${MAX_BATCH_DEVICES.value()}`});
      return;
    }

    const presentedBridgeToken = readBearerToken(req.get("authorization"));
    const bridgeRef = getFirestore().collection("bridgeRegistrations").doc(body.bridgeId);
    const bridgeSnapshot = await bridgeRef.get();

    if (!bridgeSnapshot.exists) {
      res.status(401).json({error: "Invalid bridge credentials"});
      return;
    }

    const bridge = bridgeSnapshot.data() as BridgeRegistrationDoc;
    const expectedTokenHash = hashToken(presentedBridgeToken, TOKEN_HASH_PEPPER.value());
    if (bridge.bridgeTokenHash !== expectedTokenHash) {
      res.status(401).json({error: "Invalid bridge credentials"});
      return;
    }

    if (bridge.expiresAt.toDate().getTime() < Date.now()) {
      res.status(401).json({error: "Bridge registration has expired"});
      return;
    }

    const targetDeviceIds = body.deviceIds ?? [];
    await enforceBridgeRateLimit(body.bridgeId, targetDeviceIds.length, startedAt);

    const payloadBytes = Buffer.byteLength(body.encryptedPayload, "utf8");
    const devicesCollection = bridgeRef.collection("devices");
    const targetSnapshots = await Promise.all(
      targetDeviceIds.map((deviceId) => devicesCollection.doc(deviceId).get())
    );

    let sent = 0;
    let failed = 0;
    const errors: string[] = [];
    const writeBatch = getFirestore().batch();

    for (const snapshot of targetSnapshots) {
      if (!snapshot.exists) {
        failed++;
        errors.push(`${snapshot.id}: device not found`);
        continue;
      }

      const device = snapshot.data() as DeviceRegistrationDoc;
      if (device.expiresAt.toDate().getTime() < Date.now()) {
        failed++;
        errors.push(`${snapshot.id}: token expired`);
        continue;
      }

      const message: Message = {
        token: device.fcmToken,
        notification: body.title || body.body ? {
          title: body.title ?? "Frigate Alert",
          body: body.body ?? "New Frigate event",
        } : undefined,
        data: {
          encrypted: body.encryptedPayload,
          bridgeId: body.bridgeId,
          deviceId: snapshot.id,
        },
        android: {
          priority: "high",
        },
        apns: {
          headers: {
            "apns-priority": "10",
          },
        },
      };

      const sendResult = await sendPushWithRetry(message);
      if (!sendResult.messageId) {
        failed++;
        errors.push(`${snapshot.id}: ${sendResult.errorCode ?? "fcm send failed"}`);
        if (sendResult.invalidToken) {
          writeBatch.delete(snapshot.ref);
        }
        continue;
      }

      sent++;
      writeBatch.set(
        snapshot.ref,
        {
          lastNotifiedAt: FieldValue.serverTimestamp(),
          updatedAt: FieldValue.serverTimestamp(),
          expiresAt: Timestamp.fromDate(addDays(startedAt, TOKEN_TTL_DAYS.value())),
        },
        {merge: true}
      );
    }

    await Promise.all([
      writeBatch.commit(),
      updateUsageCounters(body.bridgeId, bridge.userId, sent, failed, payloadBytes * sent, startedAt),
      updateBridgeLastUsed(body.bridgeId),
    ]);

    res.status(200).json({
      ok: failed === 0,
      bridgeId: body.bridgeId,
      requested: targetDeviceIds.length,
      sent,
      failed,
      errors,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    logger.error("sendNotification failed", {
      reason: message,
      ip: req.ip,
      origin: req.get("origin") ?? "none",
      userAgent: req.get("user-agent") ?? "unknown",
      hasAuthHeader: Boolean(req.get("authorization")),
    });

    if (message === "Rate limit exceeded") {
      res.status(429).json({error: message});
      return;
    }

    if (message.includes("invalid") || message.includes("required") || message.includes("4KB")) {
      res.status(400).json({error: message});
      return;
    }

    if (message.includes("Bearer") || message.includes("credentials") || message.includes("expired")) {
      res.status(401).json({error: message});
      return;
    }

    res.status(500).json({error: "Internal server error"});
  }
});

/**
 * exchangeGoogleToken proxies the OAuth authorization-code exchange to keep
 * GOOGLE_CLIENT_SECRET server-side. HASS calls this instead of Google directly.
 */
export const exchangeGoogleToken = onRequest(
  {...OPTIONS, secrets: [TOKEN_HASH_PEPPER, GOOGLE_CLIENT_SECRET_PARAM]},
  async (req, res) => {
    if (req.method !== "POST") {
      res.status(405).json({error: "Method not allowed"});
      return;
    }

    const {code, redirectUri} = req.body as {code?: string; redirectUri?: string};
    if (!code || !redirectUri) {
      res.status(400).json({error: "Missing code or redirectUri"});
      return;
    }

    // Basic sanity checks to prevent open-proxy abuse
    if (typeof code !== "string" || code.length > 512) {
      res.status(400).json({error: "Invalid code"});
      return;
    }
    if (typeof redirectUri !== "string" || redirectUri.length > 256) {
      res.status(400).json({error: "Invalid redirectUri"});
      return;
    }

    try {
      const params = new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID_PARAM.value(),
        client_secret: GOOGLE_CLIENT_SECRET_PARAM.value(),
        code,
        grant_type: "authorization_code",
        redirect_uri: redirectUri,
      });

      const response = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: params.toString(),
      });

      const data = await response.json() as Record<string, unknown>;
      if (!response.ok) {
        logger.warn("exchangeGoogleToken upstream failed", {status: response.status});
        res.status(400).json({error: "Token exchange failed"});
        return;
      }

      res.status(200).json({
        access_token: data.access_token,
        token_type: data.token_type,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Unknown error";
      logger.error("exchangeGoogleToken error", {reason: message});
      res.status(500).json({error: "Internal server error"});
    }
  }
);
