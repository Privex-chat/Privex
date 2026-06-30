// Integration test: load the --target web WASM in Node and exercise every
// export from Parts 1 + 2. Mirrors the Rust unit tests and additionally covers
// the Err paths (which can't run on a non-wasm host).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import init, {
  generate_identity_keypairs,
  user_id_from_ed25519,
  sign_hybrid,
  verify_hybrid,
  pqxdh_initiate,
  pqxdh_respond,
  PreKeyBundle,
  PqxdhInitMessage,
  ratchet_init_alice,
  ratchet_init_bob,
  ratchet_encrypt,
  ratchet_decrypt,
  generate_sender_cert,
  sealed_sender_encrypt,
  sealed_sender_decrypt,
  shamir_split,
  shamir_reconstruct,
  generate_seed_phrase,
  seed_phrase_to_master_seed,
  derive_keypairs_from_seed,
  opaque_register_start,
  pow_solve,
  pow_verify,
  psi_blind_hash,
  psi_check_membership,
  pdq_hash,
  hkdf_derive,
  kt_bundle_hash,
  kt_leaf_hash,
  kt_verify_inclusion,
  kt_verify_root_sig,
  generate_cek,
  wrap_cek,
  unwrap_cek,
} from "../pkg/privex_crypto_wasm.js";
import { createHash } from "node:crypto";

const wasm = readFileSync(
  new URL("../pkg/privex_crypto_wasm_bg.wasm", import.meta.url),
);
await init({ module_or_path: wasm });

const enc = (s) => new TextEncoder().encode(s);
const dec = (u) => new TextDecoder().decode(u);
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// ===== Part 1: identity, signatures, PQXDH =====
const alice = generate_identity_keypairs();
assert.equal(alice.ed25519_pub.length, 32);
const id = user_id_from_ed25519(alice.ed25519_pub);
assert.match(id, /^px_[0-9a-f]{32}$/);

const data = enc("identity assertion");
const sig = sign_hybrid(data, alice.ed25519_priv, alice.dilithium3_priv);
assert.equal(
  verify_hybrid(data, sig.sig_ed25519, alice.ed25519_pub, sig.sig_dilithium3, alice.dilithium3_pub),
  true,
);
assert.equal(
  verify_hybrid(enc("tampered"), sig.sig_ed25519, alice.ed25519_pub, sig.sig_dilithium3, alice.dilithium3_pub),
  false,
);

const bob = generate_identity_keypairs();
const spk = generate_identity_keypairs();
const opk = generate_identity_keypairs();
const bundle = new PreKeyBundle(bob.x25519_pub, spk.x25519_pub, opk.x25519_pub, bob.kyber1024_pub);
const initResult = pqxdh_initiate(alice.x25519_priv, bundle);
assert.equal(initResult.opk_used, true, "bundle had an OPK");
const pqMsg = new PqxdhInitMessage(initResult.alice_ik_pub, initResult.alice_ek_pub, initResult.kyber_ciphertext, initResult.opk_used);
const bobSecret = pqxdh_respond(pqMsg, bob.x25519_priv, spk.x25519_priv, opk.x25519_priv, bob.kyber1024_priv);
assert.ok(eq(initResult.shared_secret, bobSecret), "PQXDH secrets must agree");

// No-OPK path (server OPK supply drained → empty opk → 3-DH).
const noOpkBundle = new PreKeyBundle(bob.x25519_pub, spk.x25519_pub, new Uint8Array(0), bob.kyber1024_pub);
const initNoOpk = pqxdh_initiate(alice.x25519_priv, noOpkBundle);
assert.equal(initNoOpk.opk_used, false, "no OPK in bundle");
const pqMsgNoOpk = new PqxdhInitMessage(initNoOpk.alice_ik_pub, initNoOpk.alice_ek_pub, initNoOpk.kyber_ciphertext, initNoOpk.opk_used);
const bobSecretNoOpk = pqxdh_respond(pqMsgNoOpk, bob.x25519_priv, spk.x25519_priv, new Uint8Array(0), bob.kyber1024_priv);
assert.ok(eq(initNoOpk.shared_secret, bobSecretNoOpk), "no-OPK PQXDH secrets must agree");

// ===== Part 2: Double Ratchet =====
const shared = new Uint8Array(32).fill(7);
const bobRatchet = generate_identity_keypairs(); // use its x25519 keypair as the ratchet key
let raSession = ratchet_init_alice(shared, bobRatchet.x25519_pub);
let rbSession = ratchet_init_bob(shared, bobRatchet.x25519_priv, bobRatchet.x25519_pub);

let r = ratchet_encrypt(raSession, enc("hello bob"));
raSession = r.new_session_state;
let d = ratchet_decrypt(rbSession, r.ciphertext, r.message_header);
rbSession = d.new_session_state;
assert.equal(dec(d.plaintext), "hello bob");

// 1-byte message → 1024-byte padded plaintext (+16 GCM tag)
const onebyte = ratchet_encrypt(raSession, enc("x"));
raSession = onebyte.new_session_state;
assert.equal(onebyte.ciphertext.length, 1024 + 16);
// keep rbSession in step with the message we just sent
d = ratchet_decrypt(rbSession, onebyte.ciphertext, onebyte.message_header);
rbSession = d.new_session_state;

// out-of-order: send 1,2,3 then deliver 1,3,2
const m1 = ratchet_encrypt(raSession, enc("one"));
raSession = m1.new_session_state;
const m2 = ratchet_encrypt(raSession, enc("two"));
raSession = m2.new_session_state;
const m3 = ratchet_encrypt(raSession, enc("three"));

let dd = ratchet_decrypt(rbSession, m1.ciphertext, m1.message_header);
rbSession = dd.new_session_state;
assert.equal(dec(dd.plaintext), "one");
dd = ratchet_decrypt(rbSession, m3.ciphertext, m3.message_header);
rbSession = dd.new_session_state;
assert.equal(dec(dd.plaintext), "three");
dd = ratchet_decrypt(rbSession, m2.ciphertext, m2.message_header);
assert.equal(dec(dd.plaintext), "two"); // recovered from a skipped key

// ===== Part 2: Sealed Sender =====
const now = Math.floor(Date.now() / 1000);
const senderId = id; // alice's px id
const cert = generate_sender_cert(
  senderId,
  alice.ed25519_priv,
  alice.ed25519_pub,
  alice.dilithium3_priv,
  alice.dilithium3_pub,
  BigInt(now),
  86_400n,
);
const message = enc("ratchet ciphertext stand-in");
const blob = sealed_sender_encrypt(message, cert, bob.x25519_pub);

// sender id must not be in the outer wrapper
assert.ok(!eq(blob.slice(0, senderId.length), enc(senderId)), "sanity");
const idBytes = enc(senderId);
const leaked = Array.from({ length: blob.length - idBytes.length + 1 }).some((_, i) =>
  idBytes.every((b, j) => blob[i + j] === b),
);
assert.equal(leaked, false, "sender id must not appear in the sealed wrapper");

const sres = sealed_sender_decrypt(blob, bob.x25519_priv, BigInt(now + 1));
assert.ok(eq(sres.plaintext, message));
assert.equal(sres.sender_id, senderId);
assert.equal(sres.sender_verified, true);

// wrong recipient cannot open (Err path)
const mallory = generate_identity_keypairs();
assert.throws(() => sealed_sender_decrypt(blob, mallory.x25519_priv, BigInt(now + 1)));

// ===== Part 3: Recovery =====
// Shamir 3-of-5
const secret = new Uint8Array(32).map((_, i) => (i * 7) & 0xff);
const shares = shamir_split(secret, 3, 5);
assert.equal(shares.length, 5);
assert.ok(eq(shamir_reconstruct([shares[0], shares[2], shares[4]]), secret));
assert.throws(() => shamir_reconstruct([shares[0], shares[1]])); // below threshold → error

// Seed phrase: generate → recover → identical keypairs
const entropy = new Uint8Array(32).fill(0x42);
const phrase = generate_seed_phrase(entropy);
assert.equal(phrase.split(/\s+/).length, 24);
const masterA = seed_phrase_to_master_seed(phrase);
const masterB = seed_phrase_to_master_seed(phrase);
const kA = derive_keypairs_from_seed(masterA);
const kB = derive_keypairs_from_seed(masterB);
assert.ok(eq(kA.ed25519_pub, kB.ed25519_pub));
assert.ok(eq(kA.kyber1024_pub, kB.kyber1024_pub));
assert.throws(() => seed_phrase_to_master_seed("not a valid mnemonic")); // Err path

// OPAQUE client smoke (full round trip needs the server side → covered in cargo test)
const reg = opaque_register_start("correct horse battery staple");
assert.ok(reg.message.length > 0 && reg.client_state.length > 0);

// ===== Part 4: Utilities =====
// PoW solve → verify → tamper
const challenge = enc("privex-registration-challenge");
const sol = pow_solve(challenge, 18, undefined, undefined);
assert.equal(sol.solution_hash.length, 32);
assert.equal(pow_verify(challenge, sol.nonce, 18), true);
assert.equal(pow_verify(challenge, sol.nonce ^ 1n, 18), false); // flip nonce bit

// PSI: blind returns 32-byte point + blind; membership binary search
const blind = psi_blind_hash(enc("image-hash"));
assert.equal(blind.blinded.length, 32);
assert.equal(blind.r.length, 32);
const member = new Uint8Array(32).fill(9);
const nonMember = new Uint8Array(32).fill(1);
assert.equal(psi_check_membership(member, member), true);
assert.equal(psi_check_membership(nonMember, member), false);

// PDQ hash: 32 bytes from an RGBA image
const W = 64, H = 64;
const px = new Uint8Array(W * H * 4);
for (let i = 0; i < px.length; i++) px[i] = i & 0xff;
assert.equal(pdq_hash(px, W, H).length, 32);

// HKDF
assert.equal(hkdf_derive(enc("ikm"), enc("salt"), "privex", 48).length, 48);

// ===== Part 5: Key Transparency =====
// 0x01-domain-separated node hash (mirrors the server + wasm).
const nodeHash = (l, r) => {
  const h = createHash("sha256");
  h.update(Uint8Array.of(1));
  h.update(l);
  h.update(r);
  return new Uint8Array(h.digest());
};

const bh = (seed) =>
  kt_bundle_hash(
    new Uint8Array(32).fill(seed),
    new Uint8Array(32).fill(seed + 1),
    new Uint8Array(32).fill(seed + 2),
    new Uint8Array(32).fill(seed + 3),
    new Uint8Array(64).fill(seed + 4),
    new Uint8Array(64).fill(seed + 5),
    new Uint8Array(32).fill(seed + 6),
  );

const leafA = kt_leaf_hash("px_aaaa0000000000000000000000000a", bh(1), 100n);
const leafB = kt_leaf_hash("px_bbbb0000000000000000000000000b", bh(9), 200n);
assert.equal(leafA.length, 32);

const root = nodeHash(leafA, leafB);
// leafA: sibling leafB on the RIGHT (side 0)
const proofA = new Uint8Array(33);
proofA.set(leafB, 1);
assert.equal(kt_verify_inclusion(leafA, proofA, root), true);
// leafB: sibling leafA on the LEFT (side 1)
const proofB = new Uint8Array(33);
proofB[0] = 1;
proofB.set(leafA, 1);
assert.equal(kt_verify_inclusion(leafB, proofB, root), true);
// wrong proof / tampered root → false
assert.equal(kt_verify_inclusion(leafA, proofB, root), false);
assert.equal(kt_verify_inclusion(leafA, proofA, new Uint8Array(32)), false);
// kt_verify_root_sig is JS-callable and rejects a bogus root signature (full
// verify/tamper coverage is in the Rust unit test).
assert.equal(kt_verify_root_sig(new Uint8Array(32), new Uint8Array(64), new Uint8Array(32)), false);

// ===== Part 6: File CEK wrap/unwrap (docs 4.7) =====
const cek = generate_cek();
assert.equal(cek.length, 32);
const wrapped = wrap_cek(cek, bob.x25519_pub);
assert.ok(wrapped.wrapped.length > 32 && wrapped.eph_pub.length === 32);
assert.ok(eq(unwrap_cek(wrapped.wrapped, wrapped.eph_pub, bob.x25519_priv), cek));
// Wrong recipient cannot unwrap (Err path).
assert.throws(() => unwrap_cek(wrapped.wrapped, wrapped.eph_pub, alice.x25519_priv));

console.log("crypto-wasm part1-6 integration ok:", id);
