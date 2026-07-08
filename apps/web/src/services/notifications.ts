import { db } from "../db";

const NOTIF_KEY = "notifications_enabled";

export async function isNotificationEnabled(): Promise<boolean> {
  const row = await db.settings.get(NOTIF_KEY);
  if (row === undefined) return true;
  return row.value === true;
}

export async function setNotificationEnabled(on: boolean): Promise<void> {
  await db.settings.put({ key: NOTIF_KEY, value: on });
  if (on) {
    void subscribePush();
  } else {
    void unsubscribePush();
  }
}

export async function requestPermissionAndSubscribe(): Promise<boolean> {
  if (Notification.permission === "granted") {
    await setNotificationEnabled(true);
    return true;
  }
  if (Notification.permission === "denied") return false;
  const res = await Notification.requestPermission();
  if (res === "granted") {
    await setNotificationEnabled(true);
    return true;
  }
  return false;
}

async function subscribePush(): Promise<void> {
  try {
    if (!("serviceWorker" in navigator)) return;
    const reg = await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.getSubscription();
    if (sub) return;
    await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(
        "BCmWk7VKADMBTzQIvQnDpVpGtGXnLxHjYzRnCqVs9a0b3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5",
      ) as unknown as BufferSource,
    });
  } catch {
    // Push not configured server-side yet — silently skip.
  }
}

async function unsubscribePush(): Promise<void> {
  try {
    if (!("serviceWorker" in navigator)) return;
    const reg = await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.getSubscription();
    if (sub) await sub.unsubscribe();
  } catch {
    // Best-effort.
  }
}

function urlBase64ToUint8Array(base64: string): Uint8Array {
  const pad = "=".repeat((4 - (base64.length % 4)) % 4);
  const b64 = (base64 + pad).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}
