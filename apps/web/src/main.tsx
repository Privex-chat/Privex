import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { registerSW } from "virtual:pwa-register";
import App from "./App";
import { warmCrypto } from "./workers/crypto-client";
import "./index.css";

// Service worker: offline app shell + WASM caching (docs 9.3).
registerSW({ immediate: true });

// Load the crypto WASM module (in its worker) ahead of first use.
warmCrypto();

const root = document.getElementById("root");
if (!root) throw new Error("root element missing");

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
