// Polyfill IndexedDB for the Node test environment. WebCrypto (crypto.subtle)
// is provided by Node 20+ globally.
import "fake-indexeddb/auto";
