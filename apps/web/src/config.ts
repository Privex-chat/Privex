// Build-time constants. The KT root signing PUBLIC key is PINNED here (and
// overridable per-deployment via VITE_KT_SIGNING_PUB). It MUST come from the
// operator out-of-band - never fetched from the server that signs the roots, or
// a malicious server could sign a forged root with its own key. An empty/wrong
// pin fails closed: kt_verify_root_sig returns false and every contact is
// rejected. The default below is the local dev signer (server/.env KT_SIGNING_KEY).
export const KT_SIGNING_PUB_HEX =
  (import.meta.env.VITE_KT_SIGNING_PUB as string | undefined) ??
  "3a41ad9ebe9b8297a1d460839555eca88f97d59b96104329dd33514d60ca447a";

// Pinned Ed25519 public key for server delivery-timestamp signatures (docs 9.6).
// Same trust rule as the KT pin: distributed with the build, never fetched from
// the signing server. Wrong/empty pin fails closed - timestamps verify false and
// messages fall back to sender-claimed ordering (flagged, never dropped).
// Default = the local dev signer (server/.env TIME_SIGNING_KEY).
export const TIME_SIGNING_PUB_HEX =
  (import.meta.env.VITE_TIME_SIGNING_PUB as string | undefined) ??
  "0b41a32a8871db49dad51fc621a92db50b390d32ef0b22391a097fdf7c802c2c";
