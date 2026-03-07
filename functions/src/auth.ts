import * as crypto from "crypto";
import {Request} from "firebase-functions/v2/https";

export function hashToken(token: string, pepper: string): string {
  return crypto
    .createHmac("sha256", pepper)
    .update(token, "utf8")
    .digest("hex");
}

export function sha256Hex(payload: string): string {
  return crypto
    .createHash("sha256")
    .update(payload, "utf8")
    .digest("hex");
}

export function buildSignedRequestMessage(
  method: string,
  path: string,
  unixTimestamp: string,
  body: string
): string {
  return [
    method.toUpperCase(),
    path,
    unixTimestamp,
    sha256Hex(body),
  ].join("\n");
}

export function signRequest(
  secret: string,
  method: string,
  path: string,
  unixTimestamp: string,
  body: string
): string {
  return crypto
    .createHmac("sha256", secret)
    .update(buildSignedRequestMessage(method, path, unixTimestamp, body), "utf8")
    .digest("hex");
}

export function timingSafeEqualHex(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, "hex");
  const rightBuffer = Buffer.from(right, "hex");
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }
  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

export function isFreshUnixTimestamp(
  unixTimestamp: string,
  toleranceSeconds = 300
): boolean {
  if (!/^\d{10}$/.test(unixTimestamp)) {
    return false;
  }
  const parsed = Number(unixTimestamp);
  if (!Number.isFinite(parsed)) {
    return false;
  }
  const nowSeconds = Math.floor(Date.now() / 1000);
  return Math.abs(nowSeconds - parsed) <= toleranceSeconds;
}

export function readBearerToken(authorizationHeader: string | undefined): string {
  if (!authorizationHeader || !authorizationHeader.startsWith("Bearer ")) {
    throw new Error("Missing Bearer token");
  }

  const token = authorizationHeader.slice(7).trim();
  if (!token) {
    throw new Error("Missing Bearer token");
  }

  return token;
}

export function hasForbiddenE2EFields(payload: Record<string, unknown>): boolean {
  const forbiddenNames = [
    "e2eKey",
    "e2e_key",
    "privateKey",
    "private_key",
    "publicKey",
    "public_key",
    "encryptionKey",
    "encryption_key",
  ];

  return forbiddenNames.some((name) => Object.prototype.hasOwnProperty.call(payload, name));
}

export function getDateKey(now: Date): string {
  return now.toISOString().slice(0, 10).replace(/-/g, "");
}

export function getMinuteKey(now: Date): string {
  return now.toISOString().slice(0, 16).replace(/[-:T]/g, "");
}

export function addDays(now: Date, days: number): Date {
  const next = new Date(now);
  next.setUTCDate(next.getUTCDate() + days);
  return next;
}

export function validateBridgeOrigin(req: Request, allowedOrigins: Set<string>): boolean {
  const origin = req.get("origin");
  if (!origin) {
    return true;
  }

  if (allowedOrigins.has(origin)) {
    return true;
  }

  return /^https?:\/\/(localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})(:\d{1,5})?$/.test(origin);
}
