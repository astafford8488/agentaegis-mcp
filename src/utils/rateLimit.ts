interface RateLimitEntry {
  count: number;
  window_start: number;
}

const limits = new Map<string, RateLimitEntry>();

const DEFAULT_MAX_PER_HOUR = 10;
const DEFAULT_WINDOW_MS = 60 * 60 * 1000;

export function checkRateLimit(
  key: string,
  maxPerWindow: number = DEFAULT_MAX_PER_HOUR,
  windowMs: number = DEFAULT_WINDOW_MS
): { allowed: boolean; remaining: number; reset_at: number } {
  const now = Date.now();
  const entry = limits.get(key);

  if (!entry || now - entry.window_start > windowMs) {
    limits.set(key, { count: 1, window_start: now });
    return { allowed: true, remaining: maxPerWindow - 1, reset_at: now + windowMs };
  }

  if (entry.count >= maxPerWindow) {
    return {
      allowed: false,
      remaining: 0,
      reset_at: entry.window_start + windowMs,
    };
  }

  entry.count++;
  return {
    allowed: true,
    remaining: maxPerWindow - entry.count,
    reset_at: entry.window_start + windowMs,
  };
}

let activeScanCount = 0;
const MAX_CONCURRENT_SCANS = parseInt(process.env.MAX_CONCURRENT_SCANS || "5");

export function acquireScanSlot(): boolean {
  if (activeScanCount >= MAX_CONCURRENT_SCANS) return false;
  activeScanCount++;
  return true;
}

export function releaseScanSlot(): void {
  activeScanCount = Math.max(0, activeScanCount - 1);
}

export function getActiveScanCount(): number {
  return activeScanCount;
}
