// Typed fetch helpers for the daemon API. Every non-2xx becomes an ApiError so
// callers can surface failures as alerts — nothing is silently swallowed.
import type {
  CreateTargetBody,
  DryRunReport,
  FsListing,
  Health,
  OkReply,
  TargetSnapshot,
  TunnelStatus,
} from "./types";

export class ApiError extends Error {
  readonly status: number;
  /** Populated when the server rejects glob patterns (PUT excludes, create). */
  readonly rejected?: string[];

  constructor(status: number, message: string, rejected?: string[]) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.rejected = rejected;
  }
}

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      ...init,
      headers: init?.body ? { "Content-Type": "application/json" } : undefined,
    });
  } catch (err) {
    throw new ApiError(0, `daemon unreachable: ${errorMessage(err)}`);
  }
  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    let rejected: string[] | undefined;
    try {
      const body: unknown = await res.json();
      if (body && typeof body === "object") {
        const e = (body as { error?: unknown }).error;
        if (typeof e === "string" && e.length > 0) message = e;
        const r = (body as { rejected?: unknown }).rejected;
        if (Array.isArray(r)) rejected = r.map(String);
      }
    } catch {
      // non-JSON error body — keep the HTTP status message
    }
    throw new ApiError(res.status, message, rejected);
  }
  return (await res.json()) as T;
}

/** URL-safe slug, validated server-side too (a-z 0-9 -). */
export function isSlug(name: string): boolean {
  return /^[a-z0-9][a-z0-9-]*$/.test(name);
}

const enc = encodeURIComponent;

export const api = {
  health: (): Promise<Health> => request<Health>("/api/health"),

  tunnel: (): Promise<TunnelStatus> => request<TunnelStatus>("/api/tunnel"),

  listTargets: (): Promise<TargetSnapshot[]> => request<TargetSnapshot[]>("/api/targets"),

  getExcludes: (name: string): Promise<string[]> =>
    request<string[]>(`/api/targets/${enc(name)}/excludes`),

  putExcludes: (name: string, patterns: string[]): Promise<OkReply> =>
    request<OkReply>(`/api/targets/${enc(name)}/excludes`, {
      method: "PUT",
      body: JSON.stringify({ patterns }),
    }),

  resolve: (name: string, path: string, choice: "keep-local" | "keep-remote"): Promise<OkReply> =>
    request<OkReply>(`/api/targets/${enc(name)}/resolve`, {
      method: "POST",
      body: JSON.stringify({ path, choice }),
    }),

  pause: (name: string): Promise<OkReply> =>
    request<OkReply>(`/api/targets/${enc(name)}/pause`, { method: "POST" }),

  resume: (name: string): Promise<OkReply> =>
    request<OkReply>(`/api/targets/${enc(name)}/resume`, { method: "POST" }),

  syncNow: (name: string): Promise<OkReply> =>
    request<OkReply>(`/api/targets/${enc(name)}/sync-now`, { method: "POST" }),

  deleteTarget: (name: string): Promise<OkReply> =>
    request<OkReply>(`/api/targets/${enc(name)}`, { method: "DELETE" }),

  dryRun: (name: string): Promise<DryRunReport> =>
    request<DryRunReport>(`/api/targets/${enc(name)}/dry-run`, { method: "POST" }),

  createTarget: (body: CreateTargetBody): Promise<TargetSnapshot> =>
    request<TargetSnapshot>("/api/targets", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  fs: (path?: string): Promise<FsListing> =>
    request<FsListing>(`/api/fs${path !== undefined ? `?path=${enc(path)}` : ""}`),
};
