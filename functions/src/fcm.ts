import {getMessaging, Message} from "firebase-admin/messaging";

interface SendResult {
  messageId: string | null;
  invalidToken: boolean;
  errorCode: string | null;
  errorMessage: string | null;
}

function delayMs(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function isPermanentFCMError(code: string | undefined): boolean {
  if (!code) {
    return false;
  }

  return [
    "messaging/invalid-registration-token",
    "messaging/registration-token-not-registered",
    "messaging/invalid-argument",
  ].includes(code);
}

export async function sendPushWithRetry(message: Message): Promise<SendResult> {
  const maxRetries = 3;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const messageId = await getMessaging().send(message);
      return {
        messageId,
        invalidToken: false,
        errorCode: null,
        errorMessage: null,
      };
    } catch (error: unknown) {
      const code = (error as {code?: string}).code;
      const errorMessage = error instanceof Error ? error.message : String(error);
      if (isPermanentFCMError(code)) {
        return {
          messageId: null,
          invalidToken: code === "messaging/registration-token-not-registered" ||
            code === "messaging/invalid-registration-token",
          errorCode: code ?? null,
          errorMessage,
        };
      }

      if (attempt === maxRetries) {
        return {
          messageId: null,
          invalidToken: false,
          errorCode: code ?? "unknown",
          errorMessage,
        };
      }

      const backoffMs = (2 ** attempt) * 200 + Math.floor(Math.random() * 100);
      await delayMs(backoffMs);
    }
  }

  return {
    messageId: null,
    invalidToken: false,
    errorCode: "unknown",
    errorMessage: "Unknown FCM error",
  };
}
