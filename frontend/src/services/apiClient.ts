const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

// First-party marker required by the backend on mutating requests (CSRF guard).
const CLIENT_HEADERS = { "X-Sentinel-Client": "sentinel" };

export class ApiError extends Error {
  public readonly status: number;

  constructor(
    message: string,
    status: number,
  ) {
    super(message);
    this.status = status;
  }
}

function redirectToLogin(): void {
  if (window.location.pathname !== "/login") {
    window.location.href = "/login";
  }
}

async function refreshSession(): Promise<boolean> {
  try {
    const response = await fetch(`${API_BASE_URL}/api/auth/refresh`, {
      method: "POST",
      credentials: "include",
      headers: CLIENT_HEADERS,
    });
    return response.ok;
  } catch {
    return false;
  }
}

async function request<T>(path: string, init?: RequestInit, retry = true): Promise<T> {
  const headers = {
    ...CLIENT_HEADERS,
    ...init?.headers,
  };

  const response = await fetch(`${API_BASE_URL}/api${path}`, {
    ...init,
    headers,
    credentials: "include",
  });

  if (response.status === 401 && retry && !path.startsWith("/auth/")) {
    const refreshed = await refreshSession();
    if (refreshed) {
      return request<T>(path, init, false);
    }

    redirectToLogin();
    throw new ApiError("Session expired. Please sign in again.", 401);
  }

  if (!response.ok) {
    const body = await response.json().catch(() => null) as { detail?: string } | null;
    throw new ApiError(body?.detail ?? "The Sentinel API request failed.", response.status);
  }

  return response.json() as Promise<T>;
}

export const apiClient = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body: unknown) =>
    request<T>(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  postForm: <T>(path: string, formData: FormData) =>
    request<T>(path, { method: "POST", body: formData }),
  patch: <T>(path: string, body: unknown) =>
    request<T>(path, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
};