import { createClient } from "@supabase/supabase-js";

const url = process.env.NEXT_PUBLIC_SUPABASE_URL ?? "";
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "";

export const supabase = createClient(url, anonKey, {
  auth: { persistSession: false },
});

export interface ScanRecord {
  scan_id: string;
  target_url: string;
  scan_date: string;
  ai_summary: string | null;
}

export interface ScanDetail extends ScanRecord {
  raw_log: string | null;
}

const supabaseError = (label: string, err: unknown): Error => {
  const e = err as { message?: string; code?: string; hint?: string; details?: string };
  const parts = [e?.code, e?.message, e?.hint, e?.details].filter(Boolean);
  return new Error(parts.length ? `${label}: ${parts.join(" · ")}` : `${label}: unknown error`);
};

export async function fetchRecentScans(limit = 3): Promise<ScanRecord[]> {
  if (!url || !anonKey) throw new Error("Supabase env not configured (NEXT_PUBLIC_SUPABASE_URL / _ANON_KEY)");
  const { data, error } = await supabase
    .from("scan_logs")
    .select("scan_id, target_url, scan_date, ai_summary")
    .order("scan_date", { ascending: false })
    .limit(limit);
  if (error) throw supabaseError("scan_logs select", error);
  return (data ?? []) as ScanRecord[];
}

export async function fetchScanDetail(scanId: string): Promise<ScanDetail | null> {
  const { data, error } = await supabase
    .from("scan_logs")
    .select("scan_id, target_url, scan_date, ai_summary, raw_log")
    .eq("scan_id", scanId)
    .maybeSingle();
  if (error) throw supabaseError("scan_logs detail", error);
  return (data ?? null) as ScanDetail | null;
}
