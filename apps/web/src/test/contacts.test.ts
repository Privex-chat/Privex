import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { initCrypto, wasm } from "../crypto/wasm";
import { genIdentityBundle, fromHex, toHex, type IdentityBundle } from "../crypto/onboarding-crypto";
import {
  flattenPath,
  pqxdhInitiate,
  safetyCode,
  verifyBundle,
  isValidPxId,
} from "../crypto/contact-crypto";
import * as api from "../api/client";
import type { KeyBundleResp } from "../api/client";
import {
  acceptContact,
  addVerifiedContact,
  getContact,
  isKeyChanged,
  listContacts,
  removeContact,
  setDisplayName,
  setVerified,
  upsertInboundContact,
} from "../data/contacts";
import { addContact } from "../contacts/add";
import { solveServerPow } from "../services/pow";
import { db } from "../db";

beforeAll(async () => {
  const wasmUrl = new URL(
    "../../../../packages/crypto-wasm/pkg/privex_crypto_wasm_bg.wasm",
    import.meta.url,
  );
  await initCrypto({ module_or_path: readFileSync(wasmUrl) });
});

const entropy = (fill: number) => new Uint8Array(32).fill(fill);
const testKey = () =>
  crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

const TS = 1_900_000_000;

async function nodeHash(l: Uint8Array, r: Uint8Array): Promise<Uint8Array> {
  const buf = new Uint8Array(65);
  buf[0] = 1; // 0x01 node domain separator (mirrors kt.rs node_hash)
  buf.set(l, 1);
  buf.set(r, 33);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf as BufferSource));
}

/** Build a server-shaped key bundle response with a valid KT proof + root sig,
 *  signed by `signer`'s Ed25519 identity key. `overrides` can perturb wire fields
 *  to target a specific verification check. The leaf is always built from the
 *  ACTUAL (possibly perturbed) fields so root-sig + inclusion stay self-consistent
 *  unless a field is mutated AFTER the response is built. */
async function makeResp(
  target: IdentityBundle,
  signer: IdentityBundle,
  overrides: Partial<KeyBundleResp> = {},
): Promise<KeyBundleResp> {
  const fields = {
    user_id: target.userId,
    ik_ed25519: toHex(target.identity.ed25519_pub),
    ik_dilithium3: toHex(target.identity.dilithium3_pub),
    ik_x25519: toHex(target.identity.x25519_pub),
    spk_x25519: toHex(target.spk.pub),
    spk_sig_ed: toHex(target.spkSig.ed),
    spk_sig_dil: toHex(target.spkSig.dil),
    kyber1024_pub: toHex(target.identity.kyber1024_pub),
    opk: toHex(target.opks[0].pub) as string | null,
    opk_id: 1 as number | null,
    ...overrides,
  };

  const bundleHash = wasm.kt_bundle_hash(
    fromHex(fields.ik_ed25519),
    fromHex(fields.ik_dilithium3),
    fromHex(fields.ik_x25519),
    fromHex(fields.spk_x25519),
    fromHex(fields.spk_sig_ed),
    fromHex(fields.spk_sig_dil),
    fromHex(fields.kyber1024_pub),
  );
  const leaf = wasm.kt_leaf_hash(fields.user_id, bundleHash, BigInt(TS));
  const sibling = new Uint8Array(32).fill(0x5a);
  const root = await nodeHash(sibling, leaf); // sibling on the LEFT
  const sig = wasm.sign_hybrid(root, signer.identity.ed25519_priv, signer.identity.dilithium3_priv);

  return {
    ...fields,
    kt_proof: {
      leaf: toHex(leaf),
      path: [{ left: true, hash: toHex(sibling) }],
      root: toHex(root),
      root_sig_ed: toHex(sig.sig_ed25519),
      timestamp: TS,
    },
  };
}

describe("px_id validation", () => {
  it("accepts well-formed ids and rejects the rest", () => {
    expect(isValidPxId("px_" + "a".repeat(32))).toBe(true);
    expect(isValidPxId("px_" + "A".repeat(32))).toBe(false); // uppercase
    expect(isValidPxId("px_short")).toBe(false);
    expect(isValidPxId("not-an-id")).toBe(false);
  });
});

describe("KT bundle verification", () => {
  it("accepts a bundle with a valid proof + root signature + SPK sig", async () => {
    const target = genIdentityBundle(wasm, entropy(0x11));
    const signer = genIdentityBundle(wasm, entropy(0xaa));
    const pin = toHex(signer.identity.ed25519_pub);

    const resp = await makeResp(target, signer);
    const v = verifyBundle(wasm, pin, resp);
    expect(v.userId).toBe(target.userId);
    expect(toHex(v.ik_ed25519)).toBe(toHex(target.identity.ed25519_pub));
    expect(toHex(v.spk_x25519)).toBe(toHex(target.spk.pub));
    expect(v.opk_id).toBe(1);
  });

  it("rejects a tampered key field (recomputed leaf falls out of the proof)", async () => {
    const target = genIdentityBundle(wasm, entropy(0x12));
    const other = genIdentityBundle(wasm, entropy(0x13));
    const signer = genIdentityBundle(wasm, entropy(0xaa));
    const pin = toHex(signer.identity.ed25519_pub);

    const resp = await makeResp(target, signer);
    // Swap in someone else's identity key AFTER the proof was built → MITM shape.
    resp.ik_x25519 = toHex(other.identity.x25519_pub);
    expect(() => verifyBundle(wasm, pin, resp)).toThrow(/MITM|verification failed/i);
  });

  it("rejects a root signed by the wrong (un-pinned) key", async () => {
    const target = genIdentityBundle(wasm, entropy(0x14));
    const signer = genIdentityBundle(wasm, entropy(0xaa));
    const attacker = genIdentityBundle(wasm, entropy(0xbb));

    const resp = await makeResp(target, signer); // signed by `signer`
    // Pin the attacker's key instead → root-sig check must fail.
    expect(() => verifyBundle(wasm, toHex(attacker.identity.ed25519_pub), resp)).toThrow(
      /pinned key|verification failed/i,
    );
  });

  it("rejects an invalid SPK signature even when the proof is consistent", async () => {
    const target = genIdentityBundle(wasm, entropy(0x15));
    const signer = genIdentityBundle(wasm, entropy(0xaa));
    const pin = toHex(signer.identity.ed25519_pub);

    // Corrupt the SPK sig and build the leaf over the corrupted bytes so the
    // proof + root sig still pass - isolating the verify_hybrid check.
    const badSig = new Uint8Array(target.spkSig.ed);
    badSig[0] ^= 0xff;
    const resp = await makeResp(target, signer, { spk_sig_ed: toHex(badSig) });
    expect(() => verifyBundle(wasm, pin, resp)).toThrow(/signed prekey|verification failed/i);
  });

  it("rejects a tampered proof node (sibling hash flipped)", async () => {
    const target = genIdentityBundle(wasm, entropy(0x16));
    const signer = genIdentityBundle(wasm, entropy(0xaa));
    const pin = toHex(signer.identity.ed25519_pub);

    const resp = await makeResp(target, signer);
    const sib = fromHex(resp.kt_proof.path[0].hash);
    sib[0] ^= 0xff; // recomputed root no longer matches the signed root
    resp.kt_proof.path[0].hash = toHex(sib);
    expect(() => verifyBundle(wasm, pin, resp)).toThrow(/MITM|verification failed/i);
  });

  it("rejects a tampered root (root-sig check fails)", async () => {
    const target = genIdentityBundle(wasm, entropy(0x17));
    const signer = genIdentityBundle(wasm, entropy(0xaa));
    const pin = toHex(signer.identity.ed25519_pub);

    const resp = await makeResp(target, signer);
    const root = fromHex(resp.kt_proof.root);
    root[0] ^= 0xff; // signature was made over the original root
    resp.kt_proof.root = toHex(root);
    expect(() => verifyBundle(wasm, pin, resp)).toThrow(/pinned key|verification failed/i);
  });
});

describe("proof flattening + leaf recompute", () => {
  it("packs each path node as [side, ...32 hash] and is deterministic", () => {
    const h0 = "00".repeat(32);
    const hf = "ff".repeat(32);
    const flat = flattenPath([
      { left: true, hash: h0 },
      { left: false, hash: hf },
    ]);
    expect(flat).toHaveLength(66); // 2 nodes × 33 bytes
    expect(flat[0]).toBe(1); // left → side byte 1
    expect(toHex(flat.subarray(1, 33))).toBe(h0);
    expect(flat[33]).toBe(0); // right → side byte 0
    expect(toHex(flat.subarray(34, 66))).toBe(hf);
  });

  it("recomputes the same leaf from identical bundle fields", () => {
    const target = genIdentityBundle(wasm, entropy(0x18));
    const bh = (b: IdentityBundle) =>
      wasm.kt_bundle_hash(
        b.identity.ed25519_pub,
        b.identity.dilithium3_pub,
        b.identity.x25519_pub,
        b.spk.pub,
        b.spkSig.ed,
        b.spkSig.dil,
        b.identity.kyber1024_pub,
      );
    const leafA = wasm.kt_leaf_hash(target.userId, bh(target), BigInt(TS));
    const leafB = wasm.kt_leaf_hash(target.userId, bh(target), BigInt(TS));
    expect(toHex(leafA)).toBe(toHex(leafB));
  });
});

describe("PQXDH initiation", () => {
  it("derives a shared secret the peer reproduces with pqxdh_respond", () => {
    const bob = genIdentityBundle(wasm, entropy(0x21));
    const alice = genIdentityBundle(wasm, entropy(0x22));

    const pqx = pqxdhInitiate(wasm, alice.identity.x25519_priv, {
      ik_x25519: bob.identity.x25519_pub,
      spk_x25519: bob.spk.pub,
      opk: bob.opks[0].pub,
      kyber1024_pub: bob.identity.kyber1024_pub,
    });
    expect(pqx.opk_used).toBe(true);

    const msg = new wasm.PqxdhInitMessage(
      pqx.alice_ik_pub,
      pqx.alice_ek_pub,
      pqx.kyber_ciphertext,
      pqx.opk_used,
    );
    const bobSecret = wasm.pqxdh_respond(
      msg,
      bob.identity.x25519_priv,
      bob.spk.priv,
      bob.opks[0].priv,
      bob.identity.kyber1024_priv,
    );
    expect(toHex(bobSecret)).toBe(toHex(pqx.shared_secret));
  });

  it("falls back to the no-OPK path when the bundle has no one-time prekey", () => {
    const bob = genIdentityBundle(wasm, entropy(0x23));
    const alice = genIdentityBundle(wasm, entropy(0x24));

    const pqx = pqxdhInitiate(wasm, alice.identity.x25519_priv, {
      ik_x25519: bob.identity.x25519_pub,
      spk_x25519: bob.spk.pub,
      opk: null, // server's OPK supply drained
      kyber1024_pub: bob.identity.kyber1024_pub,
    });
    expect(pqx.opk_used).toBe(false);

    const msg = new wasm.PqxdhInitMessage(
      pqx.alice_ik_pub,
      pqx.alice_ek_pub,
      pqx.kyber_ciphertext,
      pqx.opk_used,
    );
    const bobSecret = wasm.pqxdh_respond(
      msg,
      bob.identity.x25519_priv,
      bob.spk.priv,
      new Uint8Array(0), // no OPK priv on the 3-DH path
      bob.identity.kyber1024_priv,
    );
    expect(toHex(bobSecret)).toBe(toHex(pqx.shared_secret));
  });
});

describe("safety codes", () => {
  it("are order-independent, well-formed, and change when a key changes", async () => {
    const a = genIdentityBundle(wasm, entropy(0x31)).identity.ed25519_pub;
    const b = genIdentityBundle(wasm, entropy(0x32)).identity.ed25519_pub;
    const c = genIdentityBundle(wasm, entropy(0x33)).identity.ed25519_pub;

    const ab = await safetyCode(a, b);
    const ba = await safetyCode(b, a);
    expect(ab).toBe(ba); // both parties compute the same code
    expect(ab).toMatch(/^(\d{5} ){7}\d{5}$/); // 8 groups of 5 digits
    expect(await safetyCode(a, c)).not.toBe(ab); // different key → different code
  });
});

describe("contact storage", () => {
  it("stores a verified contact with an encrypted name and a precomputed session", async () => {
    await db.contacts.clear();
    await db.sessions.clear();
    const key = await testKey();

    const target = genIdentityBundle(wasm, entropy(0x41));
    const signer = genIdentityBundle(wasm, entropy(0xaa));
    const me = genIdentityBundle(wasm, entropy(0x42));
    const v = verifyBundle(wasm, toHex(signer.identity.ed25519_pub), await makeResp(target, signer));
    const pqx = pqxdhInitiate(wasm, me.identity.x25519_priv, {
      ik_x25519: v.ik_x25519,
      spk_x25519: v.spk_x25519,
      opk: v.opk,
      kyber1024_pub: v.kyber1024_pub,
    });
    const ratchetState = wasm.ratchet_init_alice(pqx.shared_secret, v.spk_x25519);

    await addVerifiedContact(v, pqx, ratchetState, key);

    const stored = await getContact(target.userId, key);
    expect(stored?.px_id).toBe(target.userId);
    expect(stored?.verified).toBe(false);
    expect(toHex(stored!.ik_ed25519)).toBe(toHex(target.identity.ed25519_pub));

    // Session row exists: bootstrapped ratchet state + the PQXDH init stash for
    // S16's first send - both encrypted at rest.
    const session = await db.sessions.get(target.userId);
    expect(session?.ratchet_state_enc).toBeInstanceOf(Uint8Array);
    expect(session?.pqxdh_init_enc).toBeInstanceOf(Uint8Array);

    // Display name is encrypted at rest - no plaintext in the row.
    const name = "Alice 🕶";
    await setDisplayName(target.userId, name, key);
    const row = await db.contacts.get(target.userId);
    expect(toHex(row!.display_name_enc!)).not.toContain(toHex(new TextEncoder().encode(name)));
    expect((await getContact(target.userId, key))?.name).toBe(name);

    // Verification + key-change detection.
    const code = await safetyCode(me.identity.ed25519_pub, v.ik_ed25519);
    await setVerified(target.userId, code);
    expect((await getContact(target.userId, key))?.verified).toBe(true);
    expect(await isKeyChanged(target.userId, v.ik_ed25519)).toBe(false);
    expect(await isKeyChanged(target.userId, me.identity.ed25519_pub)).toBe(true);

    expect(await listContacts(key)).toHaveLength(1);

    await removeContact(target.userId);
    expect(await getContact(target.userId, key)).toBeUndefined();
    expect(await db.sessions.get(target.userId)).toBeUndefined();
  });
});

describe("addContact guard", () => {
  it("rejects a malformed px_id before any network/worker call", async () => {
    await expect(addContact("not-an-id")).rejects.toThrow(/Privex ID/);
  });
});

describe("opt-in friend requests", () => {
  it("inbound is pending; accept promotes it; once accepted it never reverts", async () => {
    await db.contacts.clear();
    const key = await testKey();
    const peer = genIdentityBundle(wasm, entropy(0x71));
    const ed = peer.identity.ed25519_pub;
    const x = peer.identity.x25519_pub;

    // Unsolicited inbound → a pending request, NOT an auto-trusted contact.
    await upsertInboundContact(peer.userId, ed, x, key);
    expect((await getContact(peer.userId, key))?.status).toBe("pending_inbound");

    // A repeat inbound hello must not change a still-pending request.
    await upsertInboundContact(peer.userId, ed, x, key);
    expect((await getContact(peer.userId, key))?.status).toBe("pending_inbound");

    // Accept → accepted, and a later inbound hello must NOT downgrade it.
    await acceptContact(peer.userId, key);
    await upsertInboundContact(peer.userId, ed, x, key);
    expect((await getContact(peer.userId, key))?.status).toBe("accepted");
  });

  it("a legacy contact (no status field) is treated as accepted and not downgraded", async () => {
    await db.contacts.clear();
    const key = await testKey();
    const peer = genIdentityBundle(wasm, entropy(0x7f));
    // A row written before the status field existed (status omitted entirely).
    await db.contacts.put({
      px_id: peer.userId,
      ik_ed25519_pub: peer.identity.ed25519_pub,
      ik_x25519_pub: peer.identity.x25519_pub,
      added_at: 0,
    });
    expect((await getContact(peer.userId, key))?.status).toBe("accepted"); // toPlain default

    // An inbound hello must NOT downgrade the legacy-accepted contact to pending
    // (would silently revoke messaging access) — and it materializes to "accepted".
    await upsertInboundContact(peer.userId, peer.identity.ed25519_pub, peer.identity.x25519_pub, key);
    expect((await getContact(peer.userId, key))?.status).toBe("accepted");
  });

  it("accepting an inbound request promotes it to accepted; a fresh add is pending_outbound", async () => {
    await db.contacts.clear();
    await db.sessions.clear();
    const key = await testKey();
    const target = genIdentityBundle(wasm, entropy(0x72));
    const signer = genIdentityBundle(wasm, entropy(0xaa));
    const me = genIdentityBundle(wasm, entropy(0x73));

    // They requested us → pending_inbound; accepting flips it to accepted.
    await upsertInboundContact(
      target.userId,
      target.identity.ed25519_pub,
      target.identity.x25519_pub,
      key,
    );
    expect((await getContact(target.userId, key))?.status).toBe("pending_inbound");
    await acceptContact(target.userId, key);
    expect((await getContact(target.userId, key))?.status).toBe("accepted");

    // A fresh deliberate add of a NEW peer → pending_outbound (Discord-style: we
    // requested them, awaiting their accept). The "once accepted" stickiness means
    // re-adding the already-accepted target above stays accepted, not downgraded.
    const other = genIdentityBundle(wasm, entropy(0x74));
    const v = verifyBundle(wasm, toHex(signer.identity.ed25519_pub), await makeResp(other, signer));
    const pqx = pqxdhInitiate(wasm, me.identity.x25519_priv, {
      ik_x25519: v.ik_x25519,
      spk_x25519: v.spk_x25519,
      opk: v.opk,
      kyber1024_pub: v.kyber1024_pub,
    });
    const ratchet = wasm.ratchet_init_alice(pqx.shared_secret, v.spk_x25519);
    await addVerifiedContact(v, pqx, ratchet, key);
    expect((await getContact(v.userId, key))?.status).toBe("pending_outbound");
  });
});

describe("client PoW gate", () => {
  it("solveServerPow assembles the proof the server consumes single-use", async () => {
    const spy = vi.spyOn(api, "powChallenge").mockResolvedValue({
      challenge_id: "cid-1",
      challenge: "00".repeat(32),
      difficulty: 4,
      expires_at: 0,
    });
    // Inject a fake solver (the real one runs in the worker / wasm).
    const proof = await solveServerPow(async () => ({
      nonce: 7,
      solutionHash: new Uint8Array([0xab, 0xcd]),
    }));
    expect(proof).toEqual({ challenge_id: "cid-1", nonce: 7, solution_hash: "abcd" });
    spy.mockRestore();
  });
});
