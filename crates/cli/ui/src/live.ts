import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import type { Health, SnapshotEvent, TargetSnapshot, TunnelStatus } from "./types";

/**
 * Live target state: initial GET + one SSE subscription to /api/events.
 *
 * - `snapshot` events replace exactly the affected target's card state.
 * - `lagged` means the server dropped broadcasts while we were slow; a full
 *   re-fetch heals the view (the daemon sends it as the client-side signal).
 * - EventSource reconnects on its own; `onerror` only flips the live badge.
 */
export function useLiveTargets(): {
  targets: TargetSnapshot[];
  health: Health | null;
  tunnel: TunnelStatus | null;
  live: boolean;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
} {
  const [map, setMap] = useState<Map<string, TargetSnapshot>>(new Map());
  const [health, setHealth] = useState<Health | null>(null);
  const [tunnel, setTunnel] = useState<TunnelStatus | null>(null);
  const [live, setLive] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const list = await api.listTargets();
      setMap(new Map(list.map((t) => [t.name, t])));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  // The tunnel's live counters (connected agents / refusals) — polled on the
  // health cadence; absent/failed = the tunnel is disabled, which is normal.
  useEffect(() => {
    let cancelled = false;
    const pull = () =>
      void api
        .tunnel()
        .then((t) => {
          if (!cancelled) setTunnel(t);
        })
        .catch(() => {
          if (!cancelled) setTunnel(null);
        });
    pull();
    const id = setInterval(pull, 15000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    void api
      .health()
      .then((h) => {
        if (!cancelled) setHealth(h);
      })
      .catch(() => {
        // surfaced through the targets error state + live badge instead
      });
    void refresh();

    const source = new EventSource("/api/events");
    source.onopen = () => {
      if (!cancelled) setLive(true);
    };
    source.onerror = () => {
      if (!cancelled) setLive(false);
    };
    source.addEventListener("snapshot", (ev: MessageEvent<string>) => {
      if (cancelled) return;
      try {
        const parsed = JSON.parse(ev.data) as SnapshotEvent;
        if (parsed && parsed.target && parsed.snapshot) {
          setMap((prev) => new Map(prev).set(parsed.target, parsed.snapshot));
        }
      } catch {
        // malformed frame — the next snapshot event or refresh heals the view
      }
    });
    source.addEventListener("removed", (ev: MessageEvent<string>) => {
      if (cancelled) return;
      try {
        const parsed = JSON.parse(ev.data) as { target?: string };
        if (parsed && parsed.target) {
          setMap((prev) => {
            const next = new Map(prev);
            next.delete(parsed.target as string);
            return next;
          });
        }
      } catch {
        // malformed frame — a refresh heals the view
      }
    });
    source.addEventListener("lagged", () => {
      if (!cancelled) void refresh();
    });

    return () => {
      cancelled = true;
      source.close();
    };
  }, [refresh]);

  const targets = [...map.values()].sort((a, b) => a.name.localeCompare(b.name));
  return { targets, health, tunnel, live, loading, error, refresh };
}

/** Ticking clock for relative timestamps ("3 min ago"). */
export function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs]);
  return now;
}

/** "just now" / "4 min ago" / "2 h ago" / fallback to a short date. */
export function relativeTime(unix: number, nowMs: number): string {
  if (!unix) return "never";
  const diffMs = nowMs - unix * 1000;
  if (diffMs < 0) return "just now";
  const s = Math.floor(diffMs / 1000);
  if (s < 10) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d} d ago`;
  return new Date(unix * 1000).toLocaleDateString();
}

export function absoluteTime(unix: number): string {
  return unix ? new Date(unix * 1000).toLocaleString() : "";
}

export function formatBytes(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 * 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  return `${(size / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
