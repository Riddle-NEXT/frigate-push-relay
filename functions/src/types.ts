export interface BridgeRegistrationDoc {
  bridgeId: string;
  userId: string;
  bridgeTokenHash: string;
  createdAt: FirebaseFirestore.Timestamp;
  updatedAt: FirebaseFirestore.Timestamp;
  lastUsedAt: FirebaseFirestore.Timestamp | null;
  expiresAt: FirebaseFirestore.Timestamp;
}

export interface DeviceRegistrationDoc {
  bridgeId: string;
  deviceId: string;
  userId: string;
  appId: string;
  fcmToken: string;
  platform: string;
  appVersion: string | null;
  subscriptionActive: boolean | null;
  subscriptionUpdatedAt: FirebaseFirestore.Timestamp | null;
  createdAt: FirebaseFirestore.Timestamp;
  updatedAt: FirebaseFirestore.Timestamp;
  lastNotifiedAt: FirebaseFirestore.Timestamp | null;
  expiresAt: FirebaseFirestore.Timestamp;
}

export interface BridgeRateLimitDoc {
  bridgeId: string;
  minuteKey: string;
  count: number;
  updatedAt: FirebaseFirestore.Timestamp;
  expiresAt: FirebaseFirestore.Timestamp;
}

export interface BridgeUsageDailyDoc {
  bridgeId: string;
  userId: string;
  dateKey: string;
  requests: number;
  sent: number;
  failed: number;
  bytesForwarded: number;
  updatedAt: FirebaseFirestore.Timestamp;
  expiresAt: FirebaseFirestore.Timestamp;
}

export interface RegisterTokenRequest {
  bridgeId: string;
  deviceId: string;
  bridgeAuthToken: string;
  fcmToken: string;
  platform: "ios" | "android" | "unknown";
  appVersion?: string;
  subscriptionActive?: boolean;
}

export interface SendNotificationRequest {
  bridgeId: string;
  encryptedPayload: string;
  title?: string;
  body?: string;
  imageUrl?: string;
  category?: string;
  threadId?: string;
  collapseId?: string;
  notificationData?: Record<string, string>;
  deviceId?: string;
  deviceIds?: string[];
}
