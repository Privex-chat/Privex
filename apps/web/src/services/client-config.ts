interface ClientConfig {
  file_uploads_enabled: boolean;
}

let cached: ClientConfig | null = null;

// Uploads stay OFF unless the server says otherwise - the same default as the
// server's FILE_UPLOADS_ENABLED (and the server refuses uploads when it's off).
const FALLBACK: ClientConfig = { file_uploads_enabled: false };

export async function getClientConfig(): Promise<ClientConfig> {
  if (cached) return cached;
  try {
    const res = await fetch("/config/client");
    if (!res.ok) return FALLBACK;
    cached = (await res.json()) as ClientConfig;
    return cached;
  } catch {
    return FALLBACK;
  }
}
