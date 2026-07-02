// Session management (docs 4.9 / 16E). "Log out everywhere" does TWO things:
//
//   1. Token revocation (already the working mechanism): POST /auth/logout_all sets
//      a per-user cutoff so every session token issued on every device dies at once
//      (auth/extract.rs rejects issued_at < cutoff). This is what actually logs
//      other devices out.
//
//   2. Signed-prekey rotation (added here): rotate the SPK so a future PQXDH init
//      can't target the OLD signed prekey - forward secrecy against a lost/seized
//      or other device that still holds the old SPK private key. This is scoped to
//      the explicit "log out everywhere" action; routine, replenish-driven SPK
//      rotation stays DECOUPLED from session life (docs/KNOWN_LIMITATIONS).
//
// NOTE (deliberate): we do NOT tie token validity to an spk_version (the build
// guide's Option C). That would log every device out on routine ~monthly rotation.
// The cutoff already invalidates tokens; SPK rotation here is orthogonal forward
// secrecy layered on top.
import * as api from "../api/client";
import { useAuth } from "../store/auth";
import { cryptoCall } from "../workers/crypto-client";
import { loadBundle, finalizeIdentity } from "../onboarding/store";
import { toHex, type SignedSpk } from "../crypto/onboarding-crypto";

export interface SessionCryptoApi {
  generateSignedSpk(edPriv: Uint8Array, dilPriv: Uint8Array): Promise<SignedSpk>;
}

export const workerSessionCrypto: SessionCryptoApi = {
  generateSignedSpk: (ed, dil) => cryptoCall("generate_signed_spk", [ed, dil]),
};

/** Log out of ALL devices: rotate the SPK (forward secrecy) then revoke every
 *  token. Order matters: spk_rotate needs the still-valid token, and logout_all
 *  revokes it. On reload this device re-authenticates (identity key unchanged) and
 *  already holds the new SPK private key persisted below, so it can keep answering
 *  inbound PQXDH sessions. */
export async function logoutEverywhere(crypto: SessionCryptoApi = workerSessionCrypto): Promise<void> {
  const bundle = await loadBundle();
  const token = useAuth.getState().sessionToken;
  if (!bundle || !token) throw new Error("not authenticated");

  const spk = await crypto.generateSignedSpk(
    bundle.identity.ed25519_priv,
    bundle.identity.dilithium3_priv,
  );

  // Server first: spk_rotate OVERWRITES the stored SPK (no OPK-style id collision)
  // and appends a KT entry. If this throws, nothing local changed - abort.
  await api.spkRotate(
    { spk_x25519_pub: toHex(spk.pub), spk_sig_ed: toHex(spk.sigEd), spk_sig_dil: toHex(spk.sigDil) },
    token,
  );

  // Persist the new SPK private key locally ONLY after the server accepted the new
  // public key (keeps device + server in sync; a future Bob answers with spk.priv).
  bundle.spk = { pub: spk.pub, priv: spk.priv };
  bundle.spkSig = { ed: spk.sigEd, dil: spk.sigDil };
  await finalizeIdentity(bundle); // rewrites priv_bundle_enc; keeps opks + mnemonic + progress

  // Revoke every token across all devices (incl. this one - we re-auth on reload).
  await api.logoutAll(token);
}
