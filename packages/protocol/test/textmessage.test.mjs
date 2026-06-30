// Interop test: TS encodes a TextMessage and must produce byte-identical wire
// output to the Rust/prost side (server/src/main.rs). Both assert the same
// shared vector, so matching it proves cross-impl compatibility.
//
// Loads the .proto via protobufjs reflection (resolves imports too). The web
// app consumes the generated static module (src/proto.js) through Vite; Node
// can't resolve protobufjs's extensionless subpath imports without a bundler,
// so the test uses reflection instead. Same schemas, same wire format.
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import protobuf from "protobufjs";

// Shared wire vector - keep in sync with EXPECTED_HEX in server/src/main.rs.
const EXPECTED_HEX = "0a0c68656c6c6f207072697665781080b4edb306";

const here = dirname(fileURLToPath(import.meta.url));
const root = await protobuf.load(join(here, "../proto/messages.proto"));
const TextMessage = root.lookupType("privex.TextMessage");

const toHex = (u8) =>
  Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");

const msg = TextMessage.create({
  body: "hello privex",
  sentAt: 1719360000,
  // expiresAfterSeconds: 0  → proto3 default, omitted from the wire
});

const bytes = TextMessage.encode(msg).finish();
const hex = toHex(bytes);
assert.equal(hex, EXPECTED_HEX, `encode mismatch: got ${hex}`);

const decoded = TextMessage.decode(bytes);
assert.equal(decoded.body, "hello privex");
assert.equal(Number(decoded.sentAt), 1719360000);
assert.equal(Number(decoded.expiresAfterSeconds), 0);

console.log("ts ok:", hex);
