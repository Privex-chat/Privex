import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { initCrypto, wasm } from "../crypto/wasm";
import { genIdentityBundle, toHex, type IdentityBundle } from "../crypto/onboarding-crypto";
import { pqxdhInitiate } from "../crypto/contact-crypto";
import {
  generateSenderCert,
  pqxdhRespond,
  ratchetDecrypt,
  ratchetEncrypt,
  ratchetInitBob,
  sealedSenderDecrypt,
  sealedSenderEncrypt,
} from "../crypto/message-crypto";
import { decodeEnvelope, decodeText, encodeEnvelope, encodeText } from "../services/envelope";

beforeAll(async () => {
  const wasmUrl = new URL(
    "../../../../packages/crypto-wasm/pkg/privex_crypto_wasm_bg.wasm",
    import.meta.url,
  );
  await initCrypto({ module_or_path: readFileSync(wasmUrl) });
});

const entropy = (fill: number) => new Uint8Array(32).fill(fill);
const NOW = 1_900_000_000;

/** Alice initiates PQXDH against Bob's prekey bundle + bootstraps her ratchet. */
function aliceStart(alice: IdentityBundle, bob: IdentityBundle, withOpk: boolean) {
  const pqx = pqxdhInitiate(wasm, alice.identity.x25519_priv, {
    ik_x25519: bob.identity.x25519_pub,
    spk_x25519: bob.spk.pub,
    opk: withOpk ? bob.opks[0].pub : null,
    kyber1024_pub: bob.identity.kyber1024_pub,
  });
  const aliceState = wasm.ratchet_init_alice(pqx.shared_secret, bob.spk.pub);
  return { pqx, aliceState };
}

/** Alice seals a ratchet-encrypted text to Bob; returns the wire blob + new state. */
function aliceSend(
  alice: IdentityBundle,
  bob: IdentityBundle,
  state: Uint8Array,
  body: string,
  pqxInit?: { alice_ik_pub: Uint8Array; alice_ek_pub: Uint8Array; kyber_ciphertext: Uint8Array; opk_used: boolean; opk_id: number },
) {
  const enc = ratchetEncrypt(wasm, state, encodeText(body, NOW));
  const envelope = encodeEnvelope(enc.header, enc.ciphertext, pqxInit);
  const cert = generateSenderCert(
    wasm,
    alice.userId,
    alice.identity.ed25519_priv,
    alice.identity.ed25519_pub,
    alice.identity.dilithium3_priv,
    alice.identity.dilithium3_pub,
    NOW,
    86_400,
  );
  const blob = sealedSenderEncrypt(wasm, envelope, cert, bob.identity.x25519_pub);
  return { blob, newState: enc.newState };
}

describe("message envelope codec", () => {
  it("round-trips text and the PQXDH init fields", () => {
    const t = decodeText(encodeText("hello 🌍", 1234));
    expect(t.body).toBe("hello 🌍");
    expect(t.sentAt).toBe(1234);

    const header = new Uint8Array([1, 2, 3]);
    const ct = new Uint8Array([9, 8, 7, 6]);
    const e = decodeEnvelope(
      encodeEnvelope(header, ct, {
        alice_ik_pub: new Uint8Array(32).fill(1),
        alice_ek_pub: new Uint8Array(32).fill(2),
        kyber_ciphertext: new Uint8Array(8).fill(3),
        opk_used: true,
        opk_id: 7,
      }),
    );
    expect(toHex(e.header)).toBe(toHex(header));
    expect(toHex(e.ciphertext)).toBe(toHex(ct));
    expect(e.pqxdh?.opk_used).toBe(true);
    expect(e.pqxdh?.opk_id).toBe(7);

    // Without a handshake the field is absent (subsequent messages).
    expect(decodeEnvelope(encodeEnvelope(header, ct)).pqxdh).toBeUndefined();
  });
});

describe("end-to-end send + receive", () => {
  it("Alice → Bob first message establishes the session and decrypts", () => {
    const alice = genIdentityBundle(wasm, entropy(0xa1));
    const bob = genIdentityBundle(wasm, entropy(0xb1));
    const { pqx, aliceState } = aliceStart(alice, bob, true);

    const { blob } = aliceSend(alice, bob, aliceState, "hello bob", {
      alice_ik_pub: pqx.alice_ik_pub,
      alice_ek_pub: pqx.alice_ek_pub,
      kyber_ciphertext: pqx.kyber_ciphertext,
      opk_used: pqx.opk_used,
      opk_id: 1,
    });

    // The outer wrapper must not leak the sender id.
    const idBytes = new TextEncoder().encode(alice.userId);
    expect(blob.length > idBytes.length).toBe(true);
    expect(
      Array.from(blob).join(",").includes(Array.from(idBytes).join(",")),
    ).toBe(false);

    // Bob opens the seal, completes PQXDH, bootstraps his ratchet, decrypts.
    const opened = sealedSenderDecrypt(wasm, blob, bob.identity.x25519_priv, NOW + 10);
    expect(opened.senderId).toBe(alice.userId);
    expect(opened.senderVerified).toBe(true);

    const env = decodeEnvelope(opened.plaintext);
    expect(env.pqxdh).toBeDefined();
    const shared = pqxdhRespond(
      wasm,
      {
        alice_ik_pub: env.pqxdh!.alice_ik_pub,
        alice_ek_pub: env.pqxdh!.alice_ek_pub,
        kyber_ciphertext: env.pqxdh!.kyber_ciphertext,
        opk_used: env.pqxdh!.opk_used,
      },
      bob.identity.x25519_priv,
      bob.spk.priv,
      bob.opks[0].priv,
      bob.identity.kyber1024_priv,
    );
    expect(toHex(shared)).toBe(toHex(pqx.shared_secret));

    const bobState = ratchetInitBob(wasm, shared, bob.spk.priv, bob.spk.pub);
    const dec = ratchetDecrypt(wasm, bobState, env.ciphertext, env.header);
    expect(decodeText(dec.plaintext).body).toBe("hello bob");
  });

  it("Bob replies and Alice decrypts (receiver→sender DH ratchet)", () => {
    const alice = genIdentityBundle(wasm, entropy(0xa2));
    const bob = genIdentityBundle(wasm, entropy(0xb2));
    const { pqx, aliceState } = aliceStart(alice, bob, true);
    const first = aliceSend(alice, bob, aliceState, "hi", {
      alice_ik_pub: pqx.alice_ik_pub,
      alice_ek_pub: pqx.alice_ek_pub,
      kyber_ciphertext: pqx.kyber_ciphertext,
      opk_used: pqx.opk_used,
      opk_id: 1,
    });

    const opened = sealedSenderDecrypt(wasm, first.blob, bob.identity.x25519_priv, NOW + 1);
    const env = decodeEnvelope(opened.plaintext);
    const shared = pqxdhRespond(
      wasm,
      {
        alice_ik_pub: env.pqxdh!.alice_ik_pub,
        alice_ek_pub: env.pqxdh!.alice_ek_pub,
        kyber_ciphertext: env.pqxdh!.kyber_ciphertext,
        opk_used: env.pqxdh!.opk_used,
      },
      bob.identity.x25519_priv,
      bob.spk.priv,
      bob.opks[0].priv,
      bob.identity.kyber1024_priv,
    );
    let bobState = ratchetInitBob(wasm, shared, bob.spk.priv, bob.spk.pub);
    bobState = ratchetDecrypt(wasm, bobState, env.ciphertext, env.header).newState;

    // Bob → Alice. Bob seals to Alice's X25519 IK (learned from pqxdh.alice_ik_pub).
    const renc = ratchetEncrypt(wasm, bobState, encodeText("hey back", NOW));
    const replyEnv = encodeEnvelope(renc.header, renc.ciphertext);
    const bobCert = generateSenderCert(
      wasm,
      bob.userId,
      bob.identity.ed25519_priv,
      bob.identity.ed25519_pub,
      bob.identity.dilithium3_priv,
      bob.identity.dilithium3_pub,
      NOW,
      86_400,
    );
    const replyBlob = sealedSenderEncrypt(wasm, replyEnv, bobCert, alice.identity.x25519_pub);

    const aOpened = sealedSenderDecrypt(wasm, replyBlob, alice.identity.x25519_priv, NOW + 2);
    expect(aOpened.senderId).toBe(bob.userId);
    const aEnv = decodeEnvelope(aOpened.plaintext);
    const aDec = ratchetDecrypt(wasm, first.newState, aEnv.ciphertext, aEnv.header);
    expect(decodeText(aDec.plaintext).body).toBe("hey back");
  });

  it("rejects a cert whose sender_id is not derived from its signing key", () => {
    const attacker = genIdentityBundle(wasm, entropy(0xc1));
    const bob = genIdentityBundle(wasm, entropy(0xc2));
    const victim = genIdentityBundle(wasm, entropy(0xc3));

    // Attacker signs a cert claiming the VICTIM's px_id with their OWN keys.
    const cert = generateSenderCert(
      wasm,
      victim.userId,
      attacker.identity.ed25519_priv,
      attacker.identity.ed25519_pub,
      attacker.identity.dilithium3_priv,
      attacker.identity.dilithium3_pub,
      NOW,
      86_400,
    );
    const blob = sealedSenderEncrypt(
      wasm,
      encodeEnvelope(new Uint8Array([1]), new Uint8Array([2])),
      cert,
      bob.identity.x25519_pub,
    );
    const opened = sealedSenderDecrypt(wasm, blob, bob.identity.x25519_priv, NOW + 1);
    expect(opened.senderId).toBe(victim.userId);
    expect(opened.senderVerified).toBe(false); // px_id not bound to the signing key
  });

  it("delivers 5 rapid messages in order (ratchet advancing)", () => {
    const alice = genIdentityBundle(wasm, entropy(0xa3));
    const bob = genIdentityBundle(wasm, entropy(0xb3));
    const { pqx, aliceState } = aliceStart(alice, bob, true);

    // First message carries the handshake; establish Bob's session from it.
    let aState = aliceState;
    const bodies = ["m0", "m1", "m2", "m3", "m4"];
    const blobs: Uint8Array[] = [];
    bodies.forEach((b, i) => {
      const sent = aliceSend(alice, bob, aState, b, i === 0
        ? {
            alice_ik_pub: pqx.alice_ik_pub,
            alice_ek_pub: pqx.alice_ek_pub,
            kyber_ciphertext: pqx.kyber_ciphertext,
            opk_used: pqx.opk_used,
            opk_id: 1,
          }
        : undefined);
      blobs.push(sent.blob);
      aState = sent.newState;
    });

    // Bob processes the first to establish the session.
    const o0 = sealedSenderDecrypt(wasm, blobs[0], bob.identity.x25519_priv, NOW + 1);
    const e0 = decodeEnvelope(o0.plaintext);
    const shared = pqxdhRespond(
      wasm,
      {
        alice_ik_pub: e0.pqxdh!.alice_ik_pub,
        alice_ek_pub: e0.pqxdh!.alice_ek_pub,
        kyber_ciphertext: e0.pqxdh!.kyber_ciphertext,
        opk_used: e0.pqxdh!.opk_used,
      },
      bob.identity.x25519_priv,
      bob.spk.priv,
      bob.opks[0].priv,
      bob.identity.kyber1024_priv,
    );
    let bState = ratchetInitBob(wasm, shared, bob.spk.priv, bob.spk.pub);
    const got: string[] = [];
    for (let i = 0; i < blobs.length; i++) {
      const o = sealedSenderDecrypt(wasm, blobs[i], bob.identity.x25519_priv, NOW + 1);
      const e = decodeEnvelope(o.plaintext);
      const d = ratchetDecrypt(wasm, bState, e.ciphertext, e.header);
      bState = d.newState;
      got.push(decodeText(d.plaintext).body);
    }
    expect(got).toEqual(bodies);
  });
});
