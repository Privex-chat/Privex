// Session management (16E): "log out everywhere" rotates the SPK for forward
// secrecy AND revokes every token via the cutoff. Verifies order (rotate with the
// still-valid token BEFORE revoke), that the new SPK private key is persisted
// locally (so this device keeps answering inbound PQXDH), and the mutual/no-op guards.
import { readFileSync } from "node:fs";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const { keyRef, wipeSpy, lockNowSpy } = vi.hoisted(() => ({
  keyRef: { key: null as CryptoKey | null },
  wipeSpy: { called: 0 },
  lockNowSpy: { called: 0 },
}));
vi.mock("../crypto/keystore", () => ({
  getMasterKey: async () => keyRef.key,
  hasMasterKey: async () => true,
  clearMasterKey: async () => {},
  wipeKeystore: async () => {
    wipeSpy.called += 1;
  },
  lockNow: () => {
    lockNowSpy.called += 1;
  },
}));

import { initCrypto, wasm } from "../crypto/wasm";
import { genIdentityBundle, toHex, type SignedSpk } from "../crypto/onboarding-crypto";
import { generateSignedSpk } from "../crypto/onboarding-crypto";
import { persistGeneratedIdentity, finalizeIdentity, loadBundle } from "../onboarding/store";
import { EncryptedMessages } from "../db/encrypted-db";
import { useAuth } from "../store/auth";
import { db } from "../db";
import * as api from "../api/client";
import { eraseThisDevice, lockApp, logoutEverywhere, type SessionCryptoApi } from "../services/session";
import * as ws from "../services/websocket";
import * as cover from "../services/cover-traffic";

beforeAll(async () => {
  await initCrypto({
    module_or_path: readFileSync(
      new URL("../../../../packages/crypto-wasm/pkg/privex_crypto_wasm_bg.wasm", import.meta.url),
    ),
  });
  keyRef.key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
});

beforeEach(async () => {
  await Promise.all([
    db.identity.clear(),
    db.settings.clear(),
    db.messages.clear(),
    db.contacts.clear(),
    db.sessions.clear(),
  ]);
  wipeSpy.called = 0;
  lockNowSpy.called = 0;
  useAuth.setState({ sessionToken: null, userId: null, authenticated: false });
});

const entropy = (f: number) => new Uint8Array(32).fill(f);

describe("log out everywhere (16E)", () => {
  it("rotates the SPK (before revoke) and persists the new private key locally", async () => {
    const me = genIdentityBundle(wasm, entropy(0x31));
    await persistGeneratedIdentity(me);
    await finalizeIdentity(me); // mark done + retain mnemonic (as after onboarding)
    useAuth.getState().setSession("tok-1", me.userId);

    const oldSpkPriv = toHex(me.spk.priv);
    const order: string[] = [];
    const rotateSpy = vi.spyOn(api, "spkRotate").mockImplementation(async () => {
      order.push("rotate");
      return { rotated: true };
    });
    const logoutSpy = vi.spyOn(api, "logoutAll").mockImplementation(async () => {
      order.push("logout");
      return { revoked: true };
    });

    // Injected crypto = the real wasm SPK generator (plain-data helper).
    const crypto: SessionCryptoApi = {
      generateSignedSpk: async (ed, dil) => generateSignedSpk(wasm, ed, dil),
    };
    await logoutEverywhere(crypto);

    // SPK rotated with the still-valid token BEFORE the token is revoked.
    expect(order).toEqual(["rotate", "logout"]);
    const rotatedArg = rotateSpy.mock.calls[0];
    expect(rotatedArg[1]).toBe("tok-1"); // authed with the pre-revocation token

    // The uploaded SPK pub is a NEW key, hybrid-signed → server would accept it.
    const uploaded = rotatedArg[0] as { spk_x25519_pub: string; spk_sig_ed: string; spk_sig_dil: string };
    expect(uploaded.spk_x25519_pub).not.toBe(toHex(me.spk.pub));

    // The new SPK PRIVATE key is persisted locally (this device can still answer
    // inbound PQXDH). The old priv is gone.
    const reloaded = await loadBundle();
    expect(toHex(reloaded!.spk.pub)).toBe(uploaded.spk_x25519_pub);
    expect(toHex(reloaded!.spk.priv)).not.toBe(oldSpkPriv);
    // Signature on the stored bundle matches the uploaded one.
    expect(toHex(reloaded!.spkSig.ed)).toBe(uploaded.spk_sig_ed);
    // Identity + mnemonic preserved (same account; seed-view still works).
    expect(reloaded!.userId).toBe(me.userId);
    expect(reloaded!.mnemonic).toBe(me.mnemonic);

    rotateSpy.mockRestore();
    logoutSpy.mockRestore();
  });

  it("does NOT revoke if the SPK rotation fails (no partial logout)", async () => {
    const me = genIdentityBundle(wasm, entropy(0x32));
    await persistGeneratedIdentity(me);
    await finalizeIdentity(me);
    useAuth.getState().setSession("tok-2", me.userId);

    const rotateSpy = vi.spyOn(api, "spkRotate").mockRejectedValue(new api.ApiError(400));
    const logoutSpy = vi.spyOn(api, "logoutAll").mockResolvedValue({ revoked: true });

    const stub: SignedSpk = {
      pub: new Uint8Array(32).fill(1),
      priv: new Uint8Array(32).fill(2),
      sigEd: new Uint8Array(64).fill(3),
      sigDil: new Uint8Array(64).fill(4),
    };
    await expect(
      logoutEverywhere({ generateSignedSpk: async () => stub }),
    ).rejects.toBeInstanceOf(api.ApiError);

    expect(logoutSpy).not.toHaveBeenCalled(); // token NOT revoked on rotate failure
    // Local SPK untouched (rotate happens server-first, persist only on success).
    expect(toHex((await loadBundle())!.spk.priv)).toBe(toHex(me.spk.priv));

    rotateSpy.mockRestore();
    logoutSpy.mockRestore();
  });

  it("throws (no calls) when not authenticated", async () => {
    const rotateSpy = vi.spyOn(api, "spkRotate");
    await expect(logoutEverywhere({ generateSignedSpk: async () => ({} as SignedSpk) })).rejects.toThrow(
      /not authenticated/,
    );
    expect(rotateSpy).not.toHaveBeenCalled();
    rotateSpy.mockRestore();
  });
});

describe("app lock teardown", () => {
  it("lockApp drops the key AND the live session (WS, cover traffic, token)", () => {
    useAuth.getState().setSession("live-token", "px_" + "aa".repeat(16));
    useAuth.getState().setAuthenticated("px_" + "aa".repeat(16));
    expect(useAuth.getState().authenticated).toBe(true);

    const disc = vi.spyOn(ws, "disconnectWebSocket").mockImplementation(() => {});
    const stopCover = vi.spyOn(cover, "stopCoverTraffic").mockImplementation(() => {});

    lockApp();

    expect(lockNowSpy.called).toBe(1); // in-memory data key dropped
    expect(disc).toHaveBeenCalled(); // WebSocket torn down
    expect(stopCover).toHaveBeenCalled(); // cover traffic stopped
    // Session dropped → the App WS effect can't reconnect while locked, and outbox
    // flush (gated on `authenticated`) stays inert.
    expect(useAuth.getState().authenticated).toBe(false);
    expect(useAuth.getState().sessionToken).toBe(null);

    disc.mockRestore();
    stopCover.mockRestore();
  });
});

describe("erase this device (16E follow-up)", () => {
  it("wipes ALL local data + keystore, signs out, and never touches the network", async () => {
    const me = genIdentityBundle(wasm, entropy(0x41));
    await persistGeneratedIdentity(me);
    await finalizeIdentity(me);
    useAuth.getState().setSession("tok", me.userId);

    // Seed data across several stores.
    await new EncryptedMessages(db).add({
      msg_id: "m1",
      session_id: "px_" + "aa".repeat(16),
      content: "secret",
      timestamp: 1,
      status: "sent",
      direction: "out",
      kind: "text",
    });
    await db.contacts.put({ px_id: "px_" + "aa".repeat(16), added_at: 1 });
    await db.settings.put({ key: "some-flag", value: true });
    expect(await db.identity.count()).toBe(1);
    expect(await db.messages.count()).toBe(1);

    // Any network call during erase would be a bug (nothing to tell the server).
    const anyPost = vi.spyOn(api, "logoutAll");
    const anyRotate = vi.spyOn(api, "spkRotate");

    await eraseThisDevice();

    // Every local store is empty.
    for (const t of db.tables) {
      expect(await t.count()).toBe(0);
    }
    // Keystore wiped + auth dropped.
    expect(wipeSpy.called).toBe(1);
    expect(useAuth.getState().authenticated).toBe(false);
    expect(useAuth.getState().sessionToken).toBe(null);
    // No server contact.
    expect(anyPost).not.toHaveBeenCalled();
    expect(anyRotate).not.toHaveBeenCalled();
    anyPost.mockRestore();
    anyRotate.mockRestore();
  });
});
