// WebAuthn PRF app-lock factor. A platform authenticator (Touch ID / Windows Hello
// / Android biometric) derives a high-entropy secret (CTAP2 hmac-secret / PRF) that
// NEVER leaves the device and is released only after the OS user-verification gate -
// the only truly brute-force-proof unlock available on the web. Feature-detected;
// when unavailable the app falls back to the Argon2id passphrase factor.

const RP_NAME = "Privex";

function rpId(): string {
  return location.hostname;
}

const bs = (u: Uint8Array): BufferSource => u as unknown as BufferSource;

// `prf` isn't in the TS WebAuthn extension types yet - narrow casts below.
type PrfExt = { prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } } };

export function webauthnSupported(): boolean {
  return typeof PublicKeyCredential !== "undefined" && !!navigator.credentials?.create;
}

export interface EnrollResult {
  credId: Uint8Array;
  prfSalt: Uint8Array;
  prfOutput: Uint8Array;
}

/** Create a platform credential with PRF and return the PRF output (the wrapping
 *  secret). Throws if the platform/browser can't do PRF app-lock. */
export async function enrollWebauthn(userId: string): Promise<EnrollResult> {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const prfSalt = crypto.getRandomValues(new Uint8Array(32));
  const userHandle = new TextEncoder().encode(`privex:${userId}`.slice(0, 64));

  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: { name: RP_NAME, id: rpId() },
      user: { id: bs(userHandle), name: "Privex", displayName: "Privex" },
      challenge: bs(challenge),
      pubKeyCredParams: [
        { type: "public-key", alg: -7 }, // ES256
        { type: "public-key", alg: -257 }, // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        residentKey: "required",
        userVerification: "required",
      },
      timeout: 60_000,
      extensions: { prf: { eval: { first: bs(prfSalt) } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("biometric setup was cancelled");

  const ext = cred.getClientExtensionResults() as PrfExt;
  if (!ext.prf?.enabled) throw new Error("this device or browser can't use a biometric app-lock");

  const credId = new Uint8Array(cred.rawId);
  // Some platforms return the PRF output at create time; others need a follow-up get.
  const first = ext.prf.results?.first;
  const prfOutput = first ? new Uint8Array(first) : await derivePrf(credId, prfSalt);
  return { credId, prfSalt, prfOutput };
}

/** Re-derive the PRF output for an existing credential (the unlock path). */
export async function derivePrf(credId: Uint8Array, prfSalt: Uint8Array): Promise<Uint8Array> {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: bs(challenge),
      rpId: rpId(),
      allowCredentials: [{ type: "public-key", id: bs(credId) }],
      userVerification: "required",
      timeout: 60_000,
      extensions: { prf: { eval: { first: bs(prfSalt) } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!assertion) throw new Error("biometric was cancelled");
  const out = (assertion.getClientExtensionResults() as PrfExt).prf?.results?.first;
  if (!out) throw new Error("biometric unlock unavailable on this device");
  return new Uint8Array(out);
}
