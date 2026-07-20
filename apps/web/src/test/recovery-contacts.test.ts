// Social-recovery RETRIEVAL (docs 4.2 path 3) — the full contact-driven flow
// against the real WASM crypto: setup seals a share to each contact; the owner
// (fresh device, no keys) opens a recovery session; each contact decrypts the
// share sealed to THEM and re-seals it to the owner's ephemeral key; the owner
// reconstructs the ORIGINAL master seed. Also: the SAS binds the code on both
// sides, and a non-contact can decrypt nothing.
import { readFileSync } from "node:fs";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const { keyRef } = vi.hoisted(() => ({ keyRef: { key: null as CryptoKey | null } }));
vi.mock("../crypto/keystore", () => ({
  getMasterKey: async () => keyRef.key,
  hasMasterKey: async () => true,
  clearMasterKey: async () => {},
}));

import { initCrypto, wasm } from "../crypto/wasm";
import { genIdentityBundle, toHex, type IdentityBundle } from "../crypto/onboarding-crypto";
import { persistGeneratedIdentity } from "../onboarding/store";
import { db } from "../db";
import * as api from "../api/client";
import {
  approveRecovery,
  parseRecoveryCode,
  recoveryCodeSas,
  startContactRecovery,
  unsealAndReconstruct,
  type ContactRecoveryCryptoApi,
} from "../services/recovery";

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
  await Promise.all([db.identity.clear(), db.settings.clear()]);
  vi.restoreAllMocks();
});

const entropy = (f: number) => new Uint8Array(32).fill(f);

// WASM-backed crypto for the flow. recoverBundleFromSeed is only reached by the
// full finalize path (poll → completeRecovery), which pulls in auth + prekey
// provisioning; these tests exercise the crypto pipeline up to the seed, so it
// is stubbed here.
const wasmCrypto: ContactRecoveryCryptoApi = {
  ephKeypair: async () => {
    const k = wasm.generate_x25519_prekey();
    return { pub: k.public_key, priv: k.private_key };
  },
  wrapCek: async (c, r) => {
    const w = wasm.wrap_cek(c, r);
    return { wrapped: w.wrapped, ephPub: w.eph_pub };
  },
  unwrapCek: async (w, e, p) => wasm.unwrap_cek(w, e, p),
  shamirReconstruct: async (shares) => wasm.shamir_reconstruct(shares),
  recoverBundleFromSeed: async () => {
    throw new Error("not used in these tests");
  },
  solvePow: async () => ({ nonce: 0, solutionHash: new Uint8Array(32) }),
};

/** Mimic setupEmergencyContacts: split O's seed (2-of-3) and seal each share to a
 *  contact's identity key → the exact blobs /recovery/shares/get would return. */
function sealSharesFor(owner: IdentityBundle, contacts: IdentityBundle[]): {
  share_index: number;
  encrypted_share: string;
}[] {
  const shares = wasm.shamir_split(owner.masterSeed, 2, contacts.length);
  return contacts.map((c, i) => {
    const w = wasm.wrap_cek(shares[i], c.identity.x25519_pub);
    const blob = new Uint8Array(w.eph_pub.length + w.wrapped.length);
    blob.set(w.eph_pub, 0);
    blob.set(w.wrapped, w.eph_pub.length);
    return { share_index: i + 1, encrypted_share: toHex(blob) };
  });
}

/** Wire the (mocked) server: a share directory + an in-memory rendezvous bucket. */
function mockServer(storedShares: { share_index: number; encrypted_share: string }[]) {
  const bucket: string[] = [];
  vi.spyOn(api, "powChallenge").mockResolvedValue({
    challenge_id: "t",
    challenge: "00",
    difficulty: 1,
    expires_at: 0,
  });
  vi.spyOn(api, "sharesGet").mockResolvedValue({ shares: storedShares });
  vi.spyOn(api, "rendezvousPost").mockImplementation(async (_rid, blobHex) => {
    bucket.push(blobHex);
    return { posted: true };
  });
  vi.spyOn(api, "rendezvousPoll").mockImplementation(async () => ({ blobs: [...bucket] }));
  return bucket;
}

describe("social recovery — contact retrieval (docs 4.2 path 3)", () => {
  it("2 of 3 contacts reconstruct the owner's original master seed", async () => {
    const owner = genIdentityBundle(wasm, entropy(0x0a));
    const contacts = [0x1a, 0x2a, 0x3a].map((f) => genIdentityBundle(wasm, entropy(f)));
    const stored = sealSharesFor(owner, contacts);
    const bucket = mockServer(stored);

    // Owner (fresh device) opens a recovery session.
    const session = await startContactRecovery(wasmCrypto);

    // The code round-trips and the SAS matches on both sides (MITM-swap defense).
    const parsed = parseRecoveryCode(session.code);
    expect(parsed.recoveryId).toBe(session.recoveryId);
    expect(toHex(parsed.rkPub)).toBe(toHex(session.rk.pub));
    expect(await recoveryCodeSas(session.code)).toBe(session.sas);

    // Two contacts approve (each loads its OWN identity to decrypt its share).
    await persistGeneratedIdentity(contacts[0]);
    await approveRecovery(session.code, owner.userId, wasmCrypto);
    await persistGeneratedIdentity(contacts[1]);
    await approveRecovery(session.code, owner.userId, wasmCrypto);
    expect(bucket).toHaveLength(2);

    // Owner unseals the posted shares and reconstructs → the ORIGINAL seed.
    const collected = new Map<string, Uint8Array>();
    const seed = await unsealAndReconstruct(session.rk.priv, bucket, collected, wasmCrypto);
    expect(seed).not.toBeNull();
    expect(toHex(seed!)).toBe(toHex(owner.masterSeed));
  });

  it("one share alone does not reconstruct (2-of-3 threshold holds)", async () => {
    const owner = genIdentityBundle(wasm, entropy(0x0b));
    const contacts = [0x1b, 0x2b, 0x3b].map((f) => genIdentityBundle(wasm, entropy(f)));
    const bucket = mockServer(sealSharesFor(owner, contacts));
    const session = await startContactRecovery(wasmCrypto);

    await persistGeneratedIdentity(contacts[0]);
    await approveRecovery(session.code, owner.userId, wasmCrypto);
    expect(bucket).toHaveLength(1);

    const seed = await unsealAndReconstruct(session.rk.priv, bucket, new Map(), wasmCrypto);
    expect(seed).toBeNull(); // below threshold — keep polling
  });

  it("a non-contact holds no share and cannot approve", async () => {
    const owner = genIdentityBundle(wasm, entropy(0x0c));
    const contacts = [0x1c, 0x2c, 0x3c].map((f) => genIdentityBundle(wasm, entropy(f)));
    mockServer(sealSharesFor(owner, contacts));
    const session = await startContactRecovery(wasmCrypto);

    const outsider = genIdentityBundle(wasm, entropy(0xff));
    await persistGeneratedIdentity(outsider);
    await expect(approveRecovery(session.code, owner.userId, wasmCrypto)).rejects.toThrow(
      /don't hold a recovery share/i,
    );
  });

  it("rejects a malformed recovery code", () => {
    expect(() => parseRecoveryCode("not-hex")).toThrow(/isn't valid/i);
    expect(() => parseRecoveryCode("abcd")).toThrow(/isn't valid/i);
  });
});
