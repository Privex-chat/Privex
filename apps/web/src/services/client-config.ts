interface ClientConfig {
  file_uploads_enabled: boolean;
}

let cached: ClientConfig | null = null;

export async function getClientConfig(): Promise<ClientConfig> {
  if (cached) return cached;
  try {
    const res = await fetch("/config/client");
    if (!res.ok) return { file_uploads_enabled: true };
    cached = (await res.json()) as ClientConfig;
    return cached;
  } catch {
    return { file_uploads_enabled: true };
  }
}
