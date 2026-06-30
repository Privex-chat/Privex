// Pure messaging crypto: Double Ratchet + Sealed Sender + PQXDH respond. Each
// helper takes the wasm module so it runs inside the crypto worker (production)
// and directly against an initialised wasm in Node tests. All wasm structs are
// converted to plain, structured-cloneable data so results cross postMessage.
import type { WasmModule } from "./onboarding-crypto";

export interface RatchetEncrypted {
  ciphertext: Uint8Array;
  header: Uint8Array;
  newState: Uint8Array;
}

export function ratchetEncrypt(w: WasmModule, state: Uint8Array, plaintext: Uint8Array): RatchetEncrypted {
  const r = w.ratchet_encrypt(state, plaintext);
  return { ciphertext: r.ciphertext, header: r.message_header, newState: r.new_session_state };
}

export interface RatchetDecrypted {
  plaintext: Uint8Array;
  newState: Uint8Array;
}

export function ratchetDecrypt(
  w: WasmModule,
  state: Uint8Array,
  ciphertext: Uint8Array,
  header: Uint8Array,
): RatchetDecrypted {
  const r = w.ratchet_decrypt(state, ciphertext, header);
  return { plaintext: r.plaintext, newState: r.new_session_state };
}

/** Bob bootstraps his ratchet from the PQXDH shared secret. His ratchet keypair
 *  is the signed prekey Alice used (docs 4.4). Returns bincode session state. */
export function ratchetInitBob(
  w: WasmModule,
  sharedSecret: Uint8Array,
  spkPriv: Uint8Array,
  spkPub: Uint8Array,
): Uint8Array {
  return w.ratchet_init_bob(sharedSecret, spkPriv, spkPub);
}

export function generateSenderCert(
  w: WasmModule,
  senderId: string,
  edPriv: Uint8Array,
  edPub: Uint8Array,
  dilPriv: Uint8Array,
  dilPub: Uint8Array,
  nowUnix: number,
  validSeconds: number,
): Uint8Array {
  return w.generate_sender_cert(senderId, edPriv, edPub, dilPriv, dilPub, BigInt(nowUnix), BigInt(validSeconds));
}

/** Seal the (already-ratchet-encrypted) envelope to the recipient's X25519
 *  identity key. The server-visible blob carries no sender identity. */
export function sealedSenderEncrypt(
  w: WasmModule,
  message: Uint8Array,
  senderCert: Uint8Array,
  recipientIkPub: Uint8Array,
): Uint8Array {
  return w.sealed_sender_encrypt(message, senderCert, recipientIkPub);
}

export interface SealedOpened {
  plaintext: Uint8Array; // the inner MessageEnvelope bytes
  senderId: string;
  senderEdPub: Uint8Array; // the cert's signing key - pin to a known contact
  senderVerified: boolean;
}

export function sealedSenderDecrypt(
  w: WasmModule,
  blob: Uint8Array,
  recipientIkPriv: Uint8Array,
  nowUnix: number,
): SealedOpened {
  const r = w.sealed_sender_decrypt(blob, recipientIkPriv, BigInt(nowUnix));
  return {
    plaintext: r.plaintext,
    senderId: r.sender_id,
    senderEdPub: r.sender_ed_pub,
    senderVerified: r.sender_verified,
  };
}

export interface PqxdhInitFields {
  alice_ik_pub: Uint8Array;
  alice_ek_pub: Uint8Array;
  kyber_ciphertext: Uint8Array;
  opk_used: boolean;
}

/** Bob completes PQXDH from Alice's init fields + his own private keys → the
 *  shared secret (equals Alice's). On the no-OPK (3-DH) path opkPriv is ignored;
 *  pass an empty Uint8Array. */
export function pqxdhRespond(
  w: WasmModule,
  init: PqxdhInitFields,
  ikPriv: Uint8Array,
  spkPriv: Uint8Array,
  opkPriv: Uint8Array,
  kyberPriv: Uint8Array,
): Uint8Array {
  const msg = new w.PqxdhInitMessage(
    init.alice_ik_pub,
    init.alice_ek_pub,
    init.kyber_ciphertext,
    init.opk_used,
  );
  return w.pqxdh_respond(msg, ikPriv, spkPriv, opkPriv, kyberPriv);
}
