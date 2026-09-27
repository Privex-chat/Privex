// key-watch: "your account was set up on another device" from the account key in
// sign-in / WS-ticket replies. Real wasm signatures, so "the server can't fake an
// alert" is tested against the actual hybrid verification.
import { readFileSync } from "node:fs";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { initCrypto, wasm } from "../crypto/wasm";
import { generateSignedSpk, genIdentityBundle, toHex, type IdentityBundle } from "../crypto/onboarding-crypto";
import { db } from "../db";
import type { AccountSpk } from "../api/client";
import { checkAccountKeys, dismissKeyAlert, hasKeyAlert, type KeyWatchDeps } from "../services/key-watch";

beforeAll(async () => {
  const wasmUrl = new URL("../../../../packages/crypto-wasm/pkg/privex_crypto_wasm_bg.wasm", import.meta.url);
  await initCrypto({ module_or_path: readFileSync(wasmUrl) });
});
beforeEach(() => db.settings.clear());

const entropy = (f: number) => new Uint8Array(32).fill(f);
const reply = (pub: Uint8Array, sigEd: Uint8Array, sigDil: Uint8Array): AccountSpk => ({
  spk_x25519: toHex(pub),
  spk_sig_ed: toHex(sigEd),
  spk_sig_dil: toHex(sigDil),
});
const deps = (me: IdentityBundle): KeyWatchDeps => ({
  loadBundle: async () => me,
  verifyHybrid: async (...a) => wasm.verify_hybrid(...a),
});
/** A new signed prekey made with this account's identity - what another device
 *  holding the account's keys (a recovery) publishes. */
const anotherDevicesKey = (me: IdentityBundle) => {
  const k = generateSignedSpk(wasm, me.identity.ed25519_priv, me.identity.dilithium3_priv);
  return reply(k.pub, k.sigEd, k.sigDil);
};

describe("account key watch", () => {
  it("stays quiet for this device's own key", async () => {
    const me = genIdentityBundle(wasm, entropy(0x41));
    await checkAccountKeys(reply(me.spk.pub, me.spkSig.ed, me.spkSig.dil), deps(me));
    await checkAccountKeys(undefined, deps(me)); // a server that predates the field
    expect(await hasKeyAlert()).toBe(false);
  });

  it("stays quiet mid-rotation, while the server still has the key we just retired", async () => {
    const me = genIdentityBundle(wasm, entropy(0x46));
    const next = generateSignedSpk(wasm, me.identity.ed25519_priv, me.identity.dilithium3_priv);
    const rotated = { ...me, spk: next, spkSig: { ed: next.sigEd, dil: next.sigDil }, prevSpks: [me.spk] };
    // First check this device ever makes: the old key is known only as retired.
    await checkAccountKeys(reply(me.spk.pub, me.spkSig.ed, me.spkSig.dil), deps(rotated));
    expect(await hasKeyAlert()).toBe(false);
  });

  it("warns about a key signed by this account that this device never made", async () => {
    const me = genIdentityBundle(wasm, entropy(0x42));
    const theirs = anotherDevicesKey(me);
    await checkAccountKeys(theirs, deps(me));
    expect(await hasKeyAlert()).toBe(true);

    // "That was me": cleared, and that key stays trusted...
    await dismissKeyAlert();
    await checkAccountKeys(theirs, deps(me));
    expect(await hasKeyAlert()).toBe(false);
    // ...but a different new one warns again.
    await checkAccountKeys(anotherDevicesKey(me), deps(me));
    expect(await hasKeyAlert()).toBe(true);
  });

  it("can't be faked by the server: keys not signed by this account never warn", async () => {
    const me = genIdentityBundle(wasm, entropy(0x43));
    const stranger = genIdentityBundle(wasm, entropy(0x44)); // validly signed, wrong account
    await checkAccountKeys(reply(stranger.spk.pub, stranger.spkSig.ed, stranger.spkSig.dil), deps(me));
    const k = generateSignedSpk(wasm, me.identity.ed25519_priv, me.identity.dilithium3_priv);
    await checkAccountKeys(reply(k.pub, new Uint8Array(64), k.sigDil), deps(me)); // bad Ed25519 sig
    await checkAccountKeys(reply(k.pub, k.sigEd, new Uint8Array(k.sigDil.length)), deps(me)); // bad Dilithium sig
    await checkAccountKeys({ spk_x25519: "zz", spk_sig_ed: "", spk_sig_dil: "" }, deps(me)); // garbage
    expect(await hasKeyAlert()).toBe(false);
  });

  it("isn't fooled by the server replaying an old key of ours this device has dropped", async () => {
    const me = genIdentityBundle(wasm, entropy(0x45));
    const old = reply(me.spk.pub, me.spkSig.ed, me.spkSig.dil);
    await checkAccountKeys(old, deps(me)); // seen while it was ours
    const next = generateSignedSpk(wasm, me.identity.ed25519_priv, me.identity.dilithium3_priv);
    const later = { ...me, spk: next, spkSig: { ed: next.sigEd, dil: next.sigDil }, prevSpks: [] };
    await checkAccountKeys(old, deps(later)); // past its retention window, replayed
    expect(await hasKeyAlert()).toBe(false);
  });
});
