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
  isFreshUnixTimestamp,
  readBearerToken,
  signRequest,
  timingSafeEqualHex,
  validateBridgeOrigin,
} from "./auth";
import {sendPushWithRetry} from "./fcm";
import {
  BridgeRegistrationDoc,
  DeviceRegistrationDoc,
  LiveActivityRequest,
  RegisterTokenRequest,
  SendNotificationRequest,
} from "./types";

initializeApp();


const TOKEN_HASH_PEPPER = defineSecret("TOKEN_HASH_PEPPER");
const GOOGLE_CLIENT_SECRET_PARAM = defineSecret("GOOGLE_CLIENT_SECRET");
const GOOGLE_CLIENT_ID_PARAM = defineString("GOOGLE_CLIENT_ID");
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
  maxInstances: 20,
  secrets: [TOKEN_HASH_PEPPER],
};

const FCM_DATA_LIMIT_BYTES = 4096;
const RELAY_CLICK_ACTION = "FLUTTER_NOTIFICATION_CLICK";
const RESERVED_NOTIFICATION_DATA_KEYS = new Set(["from"]);
const RESERVED_NOTIFICATION_DATA_PREFIXES = ["google.", "gcm."];
const LIVE_ACTIVITY_DATA_LIMIT_BYTES = 2048;

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
  const liveActivityPushToStartToken = payload.liveActivityPushToStartToken ?
    String(payload.liveActivityPushToStartToken).trim() :
    undefined;
  const liveActivityPushToken = payload.liveActivityPushToken ?
    String(payload.liveActivityPushToken).trim() :
    undefined;
  const subscriptionActive = payload.subscriptionActive;

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
  if (liveActivityPushToStartToken && !/^[A-Fa-f0-9]{32,512}$/.test(liveActivityPushToStartToken)) {
    throw new Error("liveActivityPushToStartToken is invalid");
  }
  if (liveActivityPushToken && !/^[A-Fa-f0-9]{32,512}$/.test(liveActivityPushToken)) {
    throw new Error("liveActivityPushToken is invalid");
  }
  if (
    subscriptionActive !== undefined &&
    typeof subscriptionActive !== "boolean"
  ) {
    throw new Error("subscriptionActive must be a boolean");
  }

  return {
    bridgeId,
    deviceId,
    bridgeAuthToken,
    fcmToken,
    platform: platform as "ios" | "android" | "unknown",
    appVersion,
    liveActivityPushToStartToken,
    liveActivityPushToken,
    subscriptionActive: subscriptionActive as boolean | undefined,
  };
}

function parseLiveActivity(raw: unknown): LiveActivityRequest | undefined {
  if (raw === undefined || raw === null) {
    return undefined;
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("liveActivity must be an object");
  }

  const payload = raw as Record<string, unknown>;
  const event = String(payload.event ?? "").trim().toLowerCase();
  const tokenType = payload.tokenType ? String(payload.tokenType).trim().toLowerCase() : undefined;
  const attributesType = String(payload.attributesType ?? "").trim();
  const attributes = payload.attributes;
  const contentState = payload.contentState;
  const alert = payload.alert;
  const suppressStandardPush = payload.suppressStandardPush === true;

  if (!["start", "update", "end"].includes(event)) {
    throw new Error("liveActivity event is invalid");
  }
  if (tokenType && !["push_to_start", "update"].includes(tokenType)) {
    throw new Error("liveActivity tokenType is invalid");
  }
  if (!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(attributesType)) {
    throw new Error("liveActivity attributesType is invalid");
  }
  if (!contentState || typeof contentState !== "object" || Array.isArray(contentState)) {
    throw new Error("liveActivity contentState must be an object");
  }
  if (attributes !== undefined && (!attributes || typeof attributes !== "object" || Array.isArray(attributes))) {
    throw new Error("liveActivity attributes must be an object");
  }
  if (event === "start" && attributes === undefined) {
    throw new Error("liveActivity start requires attributes");
  }
  if (alert !== undefined && (!alert || typeof alert !== "object" || Array.isArray(alert))) {
    throw new Error("liveActivity alert must be an object");
  }

  const contentStateBytes = Buffer.byteLength(JSON.stringify(contentState), "utf8");
  const attributesBytes = Buffer.byteLength(JSON.stringify(attributes ?? {}), "utf8");
  if (contentStateBytes > LIVE_ACTIVITY_DATA_LIMIT_BYTES || attributesBytes > LIVE_ACTIVITY_DATA_LIMIT_BYTES) {
    throw new Error("liveActivity payload is too large");
  }

  const parsedAlert = alert as Record<string, unknown> | undefined;
  const title = parsedAlert?.title ? String(parsedAlert.title).trim() : undefined;
  const body = parsedAlert?.body ? String(parsedAlert.body).trim() : undefined;
  if (title && title.length > 120) {
    throw new Error("liveActivity alert title is too long");
  }
  if (body && body.length > 500) {
    throw new Error("liveActivity alert body is too long");
  }

  function optionalUnixSeconds(value: unknown, fieldName: string): number | undefined {
    if (value === undefined || value === null || value === "") return undefined;
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed < 0) {
      throw new Error(`liveActivity ${fieldName} is invalid`);
    }
    return Math.floor(parsed);
  }

  return {
    event: event as "start" | "update" | "end",
    tokenType: tokenType as "push_to_start" | "update" | undefined,
    attributesType,
    attributes: attributes ? attributes as Record<string, unknown> : undefined,
    contentState: contentState as Record<string, unknown>,
    timestamp: optionalUnixSeconds(payload.timestamp, "timestamp"),
    staleDate: optionalUnixSeconds(payload.staleDate, "staleDate"),
    dismissalDate: optionalUnixSeconds(payload.dismissalDate, "dismissalDate"),
    alert: title || body ? {title, body} : undefined,
    suppressStandardPush,
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
  const imageUrl = payload.imageUrl ? String(payload.imageUrl).trim() : undefined;
  const category = payload.category ? String(payload.category).trim() : undefined;
  const threadId = payload.threadId ? String(payload.threadId).trim() : undefined;
  const collapseId = payload.collapseId ?
    String(payload.collapseId).trim() :
    payload.collapseKey ?
      String(payload.collapseKey).trim() :
      undefined;
  const singleDeviceId = payload.deviceId ? String(payload.deviceId).trim() : undefined;
  const listDeviceIds = Array.isArray(payload.deviceIds) ? payload.deviceIds : [];
  const rawNotificationData = payload.notificationData;
  const liveActivity = parseLiveActivity(payload.liveActivity);

  if (!/^[A-Za-z0-9._:-]{3,128}$/.test(bridgeId)) {
    throw new Error("bridgeId is invalid");
  }
  if (!encryptedPayload) {
    throw new Error("encryptedPayload is required");
  }

  const payloadBytes = Buffer.byteLength(encryptedPayload, "utf8");
  if (payloadBytes > FCM_DATA_LIMIT_BYTES) {
    throw new Error("encryptedPayload exceeds 4KB limit");
  }
  if (title && title.length > 120) {
    throw new Error("title is too long");
  }
  if (msgBody && msgBody.length > 500) {
    throw new Error("body is too long");
  }
  if (imageUrl && imageUrl.length > 2048) {
    throw new Error("imageUrl is too long");
  }
  if (category && !/^[A-Za-z0-9_.-]{1,64}$/.test(category)) {
    throw new Error("category is invalid");
  }
  if (threadId && threadId.length > 64) {
    throw new Error("threadId is too long");
  }
  if (collapseId && collapseId.length > 64) {
    throw new Error("collapseId is too long");
  }

  let notificationData: Record<string, string> | undefined;
  if (rawNotificationData !== undefined) {
    if (!rawNotificationData || typeof rawNotificationData !== "object" || Array.isArray(rawNotificationData)) {
      throw new Error("notificationData must be an object");
    }

    notificationData = {};
    for (const [key, value] of Object.entries(rawNotificationData as Record<string, unknown>)) {
      const normalizedKey = String(key).trim();
      if (!/^[A-Za-z0-9_.-]{1,64}$/.test(normalizedKey)) {
        throw new Error("notificationData contains an invalid key");
      }
      if (
        RESERVED_NOTIFICATION_DATA_KEYS.has(normalizedKey) ||
        RESERVED_NOTIFICATION_DATA_PREFIXES.some((prefix) => normalizedKey.startsWith(prefix))
      ) {
        throw new Error("notificationData contains a reserved key");
      }

      const normalizedValue = String(value ?? "");
      if (normalizedValue.length > 1024) {
        throw new Error("notificationData contains a value that is too long");
      }
      notificationData[normalizedKey] = normalizedValue;
    }
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
    imageUrl,
    category,
    threadId,
    collapseId,
    notificationData,
    liveActivity,
    deviceIds: [...deviceIds],
  };
}

function estimateFcmDataBytes(data: Record<string, string>): number {
  return Buffer.byteLength(JSON.stringify(data), "utf8");
}

function buildRelayMessageData(
  body: SendNotificationRequest,
  deviceId: string
): Record<string, string> {
  const data: Record<string, string> = {
    encrypted: body.encryptedPayload,
    bridgeId: body.bridgeId,
    deviceId,
    click_action: RELAY_CLICK_ACTION,
    ...(body.collapseId ? {collapseId: body.collapseId} : {}),
    ...(body.notificationData ?? {}),  // Will be empty now - full E2E encryption
  };

  return data;
}

function assertFcmPayloadFits(body: SendNotificationRequest): void {
  const deviceIds = body.deviceIds ?? [];
  const maxDataBytes = deviceIds.reduce((maxBytes, deviceId) => {
    const currentBytes = estimateFcmDataBytes(buildRelayMessageData(body, deviceId));
    return Math.max(maxBytes, currentBytes);
  }, 0);

  if (maxDataBytes > FCM_DATA_LIMIT_BYTES) {
    throw new Error(`FCM data payload exceeds 4KB limit (${maxDataBytes} bytes)`);
  }
}

function buildLiveActivityMessage(
  body: SendNotificationRequest,
  device: DeviceRegistrationDoc,
  token: string
): Message {
  const live = body.liveActivity!;
  const aps: Record<string, unknown> = {
    timestamp: live.timestamp ?? Math.floor(Date.now() / 1000),
    event: live.event,
    "content-state": live.contentState,
  };
  if (live.event === "start") {
    aps["attributes-type"] = live.attributesType;
    aps.attributes = live.attributes ?? {};
  }
  if (live.staleDate !== undefined) {
    aps["stale-date"] = live.staleDate;
  }
  if (live.dismissalDate !== undefined) {
    aps["dismissal-date"] = live.dismissalDate;
  }
  if (live.alert?.title || live.alert?.body) {
    aps.alert = {
      ...(live.alert.title ? {title: live.alert.title} : {}),
      ...(live.alert.body ? {body: live.alert.body} : {}),
    };
  }

  return {
    token: device.fcmToken,
    apns: {
      liveActivityToken: token,
      headers: {
        "apns-priority": live.event === "update" ? "5" : "10",
      },
      payload: {aps},
    },
  };
}

function isBadRequestMessage(message: string): boolean {
  return [
    "invalid",
    "required",
    "4KB",
    "too long",
    "must be",
    "reserved",
    "liveActivity",
    "At least one target deviceId",
    "Request body must be a JSON object",
    "Relay does not process E2E keys",
    "FCM data payload exceeds",
  ].some((needle) => message.includes(needle));
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
    logger.info("registerToken request accepted", {
      bridgeId: body.bridgeId,
      deviceId: body.deviceId,
      platform: body.platform,
      subscriptionActive: body.subscriptionActive ?? null,
      uid: identity.uid,
      appId: identity.appId,
      hasAuthHeader: Boolean(req.get("authorization")),
      hasAppCheckHeader: Boolean(req.get("X-Firebase-AppCheck")),
      ip: req.ip,
      userAgent: req.get("user-agent") ?? "unknown",
    });
    const now = new Date();
    const db = getFirestore();
    const pepper = TOKEN_HASH_PEPPER.value();
    const bridgeTokenHash = hashToken(body.bridgeAuthToken, pepper);
    const expiresAt = Timestamp.fromDate(addDays(now, TOKEN_TTL_DAYS.value()));
    const bridgeRef = db.collection("bridgeRegistrations").doc(body.bridgeId);
    const deviceRef = bridgeRef.collection("devices").doc(body.deviceId);

    await db.runTransaction(async (transaction) => {
      const [bridgeSnapshot, deviceSnapshot] = await Promise.all([
        transaction.get(bridgeRef),
        transaction.get(deviceRef),
      ]);
      const existingBridge = bridgeSnapshot.exists ?
        bridgeSnapshot.data() as BridgeRegistrationDoc :
        undefined;
      const existingDevice = deviceSnapshot.exists ?
        deviceSnapshot.data() as DeviceRegistrationDoc :
        undefined;

      if (
        existingBridge?.bridgeTokenHash &&
          existingBridge.bridgeTokenHash !== bridgeTokenHash &&
          existingBridge.lastUsedAt
      ) {
        throw new Error("bridgeAuthToken does not match existing bridge registration");
      }

      const effectiveBridgeTokenHash = existingBridge?.lastUsedAt ?
        existingBridge.bridgeTokenHash :
        bridgeTokenHash;

      transaction.set(
        bridgeRef,
        {
          bridgeId: body.bridgeId,
          userId: existingBridge?.userId ?? identity.uid,
          bridgeTokenHash: effectiveBridgeTokenHash,
          createdAt: existingBridge?.createdAt ?? Timestamp.now(),
          updatedAt: FieldValue.serverTimestamp(),
          lastUsedAt: existingBridge?.lastUsedAt ?? null,
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
          liveActivityPushToStartToken: body.liveActivityPushToStartToken ??
            existingDevice?.liveActivityPushToStartToken ??
            null,
          liveActivityPushToken: body.liveActivityPushToken ??
            existingDevice?.liveActivityPushToken ??
            null,
          subscriptionActive: body.subscriptionActive ?? existingDevice?.subscriptionActive ?? null,
          subscriptionUpdatedAt: body.subscriptionActive === undefined ?
            existingDevice?.subscriptionUpdatedAt ?? null :
            FieldValue.serverTimestamp(),
          createdAt: existingDevice?.createdAt ?? FieldValue.serverTimestamp(),
          updatedAt: FieldValue.serverTimestamp(),
          lastNotifiedAt: existingDevice?.lastNotifiedAt ?? null,
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
    logger.info("registerToken success", {
      bridgeId: body.bridgeId,
      deviceId: body.deviceId,
      subscriptionActive: body.subscriptionActive ?? null,
      uid: identity.uid,
      appId: identity.appId,
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

    if (
      message.includes("App Check") ||
      message.includes("Bearer") ||
      message.includes("linked") ||
      message.includes("bridgeAuthToken")
    ) {
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
    logger.warn("sendNotification rejected: origin not allowed", {
      origin: origin ?? "none",
      ip: req.ip,
      userAgent: req.get("user-agent") ?? "unknown",
    });
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
    const encryptedPayloadBytes = Buffer.byteLength(body.encryptedPayload, "utf8");
    logger.info("sendNotification request accepted", {
      bridgeId: body.bridgeId,
      requestedDevices: body.deviceIds?.length ?? 0,
      encryptedPayloadBytes,
      hasImageUrl: Boolean(body.imageUrl),
      hasAuthHeader: Boolean(req.get("authorization")),
      origin: req.get("origin") ?? "none",
      ip: req.ip,
      userAgent: req.get("user-agent") ?? "unknown",
    });
    if ((body.deviceIds?.length ?? 0) > MAX_BATCH_DEVICES.value()) {
      res.status(400).json({error: `deviceIds exceeds max batch size of ${MAX_BATCH_DEVICES.value()}`});
      return;
    }

    const presentedBridgeToken = readBearerToken(req.get("authorization"));
    const presentedTimestamp = String(req.get("X-Frigate-Timestamp") ?? "").trim();
    const presentedSignature = String(req.get("X-Frigate-Signature") ?? "").trim().toLowerCase();
    const rawBody = Buffer.isBuffer(req.rawBody) ?
      req.rawBody.toString("utf8") :
      JSON.stringify(req.body ?? {});
    const bridgeRef = getFirestore().collection("bridgeRegistrations").doc(body.bridgeId);
    const bridgeSnapshot = await bridgeRef.get();

    if (!bridgeSnapshot.exists) {
      logger.warn("sendNotification rejected: bridge not found", {
        bridgeId: body.bridgeId,
        requestedDevices: body.deviceIds?.length ?? 0,
      });
      res.status(401).json({error: "Invalid bridge credentials"});
      return;
    }

    const bridge = bridgeSnapshot.data() as BridgeRegistrationDoc;
    const expectedTokenHash = hashToken(presentedBridgeToken, TOKEN_HASH_PEPPER.value());
    if (bridge.bridgeTokenHash !== expectedTokenHash) {
      logger.warn("sendNotification rejected: bridge token mismatch", {
        bridgeId: body.bridgeId,
        requestedDevices: body.deviceIds?.length ?? 0,
      });
      res.status(401).json({error: "Invalid bridge credentials"});
      return;
    }

    if (!isFreshUnixTimestamp(presentedTimestamp)) {
      logger.warn("sendNotification rejected: stale or invalid timestamp", {
        bridgeId: body.bridgeId,
        timestamp: presentedTimestamp || "missing",
      });
      res.status(401).json({error: "Invalid or expired request signature"});
      return;
    }

    if (!/^[a-f0-9]{64}$/.test(presentedSignature)) {
      logger.warn("sendNotification rejected: missing or invalid signature", {
        bridgeId: body.bridgeId,
      });
      res.status(401).json({error: "Invalid or expired request signature"});
      return;
    }

    const expectedSignature = signRequest(
      presentedBridgeToken,
      req.method,
      req.path,
      presentedTimestamp,
      rawBody
    );
    if (!timingSafeEqualHex(expectedSignature, presentedSignature)) {
      logger.warn("sendNotification rejected: signature mismatch", {
        bridgeId: body.bridgeId,
        path: req.path,
      });
      res.status(401).json({error: "Invalid or expired request signature"});
      return;
    }

    if (bridge.expiresAt.toDate().getTime() < Date.now()) {
      logger.warn("sendNotification rejected: bridge registration expired", {
        bridgeId: body.bridgeId,
        expiresAt: bridge.expiresAt.toDate().toISOString(),
      });
      res.status(401).json({error: "Bridge registration has expired"});
      return;
    }

    const targetDeviceIds = body.deviceIds ?? [];
    await enforceBridgeRateLimit(body.bridgeId, targetDeviceIds.length, startedAt);
    assertFcmPayloadFits(body);

    const payloadBytes = Buffer.byteLength(body.encryptedPayload, "utf8");
    const devicesCollection = bridgeRef.collection("devices");
    const targetSnapshots = await Promise.all(
      targetDeviceIds.map((deviceId) => devicesCollection.doc(deviceId).get())
    );

    let sent = 0;
    let failed = 0;
    const errors: string[] = [];
    const deliveryFailures: Array<{
      deviceId: string;
      platform: string;
      appVersion: string | null;
      appId: string;
      invalidToken: boolean;
      errorCode: string;
      errorMessage: string | null;
    }> = [];
    const writeBatch = getFirestore().batch();

    const notificationTitle = body.title ?? "Frigate Alert";
    const notificationBody = body.body ?? "New Frigate event";

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
      if (device.subscriptionActive === false) {
        failed++;
        errors.push(`${snapshot.id}: subscription inactive`);
        deliveryFailures.push({
          deviceId: snapshot.id,
          platform: device.platform,
          appVersion: device.appVersion,
          appId: device.appId,
          invalidToken: false,
          errorCode: "subscription-inactive",
          errorMessage: "Device push subscription is inactive",
        });
        continue;
      }

      const notification: {title: string; body: string; imageUrl?: string} = {
        title: notificationTitle,
        body: notificationBody,
      };
      if (body.imageUrl) {
        notification.imageUrl = body.imageUrl;
      }

      let liveActivityDelivered = false;
      if (body.liveActivity && device.platform === "ios") {
        const liveToken = body.liveActivity.event === "start" ||
          body.liveActivity.tokenType === "push_to_start" ?
          device.liveActivityPushToStartToken :
          device.liveActivityPushToken;
        if (liveToken) {
          const liveResult = await sendPushWithRetry(
            buildLiveActivityMessage(body, device, liveToken)
          );
          if (liveResult.messageId) {
            liveActivityDelivered = true;
            logger.info("sendNotification live activity sent", {
              bridgeId: body.bridgeId,
              deviceId: snapshot.id,
              event: body.liveActivity.event,
              tokenType: body.liveActivity.event === "start" ? "push_to_start" : "update",
            });
          } else {
            logger.warn("sendNotification live activity failed", {
              bridgeId: body.bridgeId,
              deviceId: snapshot.id,
              event: body.liveActivity.event,
              errorCode: liveResult.errorCode,
              errorMessage: liveResult.errorMessage,
            });
          }
        }
      }

      if (liveActivityDelivered && body.liveActivity?.suppressStandardPush) {
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
        continue;
      }

      const androidNotification: {
        channelId: string;
        imageUrl?: string;
        tag?: string;
        clickAction: string;
      } = {
        channelId: "frigate_alerts",
        clickAction: RELAY_CLICK_ACTION,
      };
      if (body.imageUrl) {
        androidNotification.imageUrl = body.imageUrl;
      }
      if (body.collapseId) {
        androidNotification.tag = body.collapseId;
      } else if (body.threadId) {
        androidNotification.tag = body.threadId;
      }

      const aps: Record<string, unknown> = {
        sound: "default",
        mutableContent: true,
      };
      if (body.category) {
        aps.category = body.category;
      }
      if (body.threadId) {
        aps.threadId = body.threadId;
      }

      const apnsHeaders: Record<string, string> = {
        "apns-priority": "10",
        "apns-push-type": "alert",
      };
      if (body.collapseId) {
        apnsHeaders["apns-collapse-id"] = body.collapseId;
      }

      const message: Message = {
        token: device.fcmToken,
        notification,
        data: {
          ...buildRelayMessageData(body, snapshot.id),
        },
        android: {
          priority: "high",
          collapseKey: body.collapseId,
          notification: androidNotification,
        },
        apns: {
          headers: apnsHeaders,
          payload: {
            aps,
          },
        },
      };

      const sendResult = await sendPushWithRetry(message);
      if (!sendResult.messageId) {
        failed++;
        const errorCode = sendResult.errorCode ?? "fcm send failed";
        errors.push(`${snapshot.id}: ${errorCode}`);
        deliveryFailures.push({
          deviceId: snapshot.id,
          platform: device.platform,
          appVersion: device.appVersion,
          appId: device.appId,
          invalidToken: sendResult.invalidToken,
          errorCode,
          errorMessage: sendResult.errorMessage,
        });
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
      deliveryFailures,
    });
    logger.info("sendNotification result", {
      bridgeId: body.bridgeId,
      requested: targetDeviceIds.length,
      sent,
      failed,
      errorCount: errors.length,
      errors,
      failureSummaries: deliveryFailures.map((failure) => ({
        deviceId: failure.deviceId,
        platform: failure.platform,
        appVersion: failure.appVersion,
        errorCode: failure.errorCode,
        invalidToken: failure.invalidToken,
        errorMessage: failure.errorMessage,
      })),
      deliveryFailures,
    });
    if (deliveryFailures.length > 0) {
      logger.warn("sendNotification delivery failures", {
        bridgeId: body.bridgeId,
        failureCount: deliveryFailures.length,
        deliveryFailures,
      });
    }
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

    if (isBadRequestMessage(message)) {
      // Extract payload size info if available for debugging
      const sizeMatch = message.match(/\((\d+)\s*bytes\)/);
      const payloadSize = sizeMatch ? parseInt(sizeMatch[1], 10) : undefined;
      res.status(400).json({
        error: message,
        payloadSize,
        limit: FCM_DATA_LIMIT_BYTES,
        hint: payloadSize && payloadSize > FCM_DATA_LIMIT_BYTES
          ? "Reduce encryptedPayload size, remove image URLs, or trim notificationData fields"
          : undefined,
      });
      return;
    }

    if (message.includes("Bearer") || message.includes("credentials") || message.includes("expired") || message.includes("signature")) {
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
