// Small byte helpers shared by the message + file services. base64 works in both
// the browser and the Node test env (btoa/atob are globals in Node 18+).

export function b64encode(u: Uint8Array): string {
  let s = "";
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s);
}

export function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}

// TS 5.7 made TypedArrays generic over their backing buffer; WebCrypto wants
// `BufferSource`. Our arrays are always ArrayBuffer-backed, so assert it.
export const src = (u: Uint8Array): BufferSource => u as unknown as BufferSource;
