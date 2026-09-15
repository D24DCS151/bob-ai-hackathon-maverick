/**
 * THREATICAP API Client
 * 
 * Production-grade client for the THREATICAP backend API v1.
 * Supports X-API-Key and Bearer JWT authentication.
 * Uses fetch with automatic error handling and type serialization.
 */

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8080";
const DEFAULT_API_KEY = process.env.NEXT_PUBLIC_DEFAULT_API_KEY || "";

function getAuthHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  // Try X-API-Key first, then Bearer JWT
  const apiKey = typeof window !== "undefined" 
    ? localStorage.getItem("threaticap_api_key") 
    : DEFAULT_API_KEY;

  if (apiKey) {
    headers["X-API-Key"] = apiKey;
  } else {
    const token = typeof window !== "undefined"
      ? localStorage.getItem("threaticap_token")
      : null;
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  }

  return headers;
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE_URL}/api/v1${endpoint}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      ...getAuthHeaders(),
      ...options.headers,
    },
    credentials: "include",
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(
      errorData.detail || errorData.error || `API request failed: ${response.status}`
    );
  }

  // Some endpoints return 204 No Content
  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}

// Alias for convenience
export const api = { request };

export type { RequestInit };

export type {
  RequestInit as ApiRequestInit,
};