"use client";

import { motion, AnimatePresence } from "framer-motion";
import {
  History,
  RefreshCw,
  Globe,
  ChevronRight,
  Sparkles,
  AlertTriangle,
  CheckCircle2,
  CircleDashed,
} from "lucide-react";
import { useEffect, useState, useCallback } from "react";
import { fetchRecentScans, type ScanRecord } from "@/lib/supabase";

interface Props {
  onOpenScan: (record: ScanRecord) => void;
  refreshKey: number;
}

const relativeTime = (iso: string): string => {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const diff = (Date.now() - t) / 1000;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 86400 * 7) return `${Math.floor(diff / 86400)}d ago`;
  return new Date(iso).toLocaleDateString();
};

const verdictFromSummary = (
  summary: string | null
): { tone: "critical" | "warn" | "clean" | "unknown"; label: string } => {
  if (!summary) return { tone: "unknown", label: "no summary" };
  const lower = summary.toLowerCase();
  if (/\b(critical|webshell|compromised|breach|backdoor|not safe|immediate)\b/.test(lower)) {
    return { tone: "critical", label: "critical" };
  }
  if (/\b(warning|outdated|potential|blocked|incomplete)\b/.test(lower)) {
    return { tone: "warn", label: "warning" };
  }
  if (/\b(safe|clean|no issues|no critical)\b/.test(lower)) {
    return { tone: "clean", label: "clean" };
  }
  return { tone: "unknown", label: "review" };
};

const verdictStyles: Record<
  ReturnType<typeof verdictFromSummary>["tone"],
  { ring: string; chip: string; icon: typeof AlertTriangle }
> = {
  critical: {
    ring: "border-red-400/30 hover:border-red-400/55 hover:shadow-[0_0_24px_rgba(248,113,113,0.12)]",
    chip: "bg-red-400/12 border-red-400/40 text-red-300",
    icon: AlertTriangle,
  },
  warn: {
    ring: "border-amber-300/30 hover:border-amber-300/55 hover:shadow-[0_0_24px_rgba(252,211,77,0.12)]",
    chip: "bg-amber-300/10 border-amber-300/35 text-amber-200",
    icon: AlertTriangle,
  },
  clean: {
    ring: "border-primary/25 hover:border-primary/55 hover:shadow-[0_0_24px_rgba(34,197,94,0.12)]",
    chip: "bg-primary/12 border-primary/35 text-primary",
    icon: CheckCircle2,
  },
  unknown: {
    ring: "border-border-col hover:border-slate-500",
    chip: "bg-slate-700/40 border-slate-600 text-slate-400",
    icon: CircleDashed,
  },
};

const hostname = (raw: string): string => {
  try {
    return new URL(raw).hostname;
  } catch {
    return raw.replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
  }
};

export default function ScanHistory({ onOpenScan, refreshKey }: Props) {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchRecentScans(3);
      setScans(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load scans");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load, refreshKey]);

  return (
    <section
      className="rounded-2xl border border-border-col bg-card overflow-hidden"
      aria-label="Recent scan history"
    >
      <header className="flex items-center justify-between gap-3 px-5 py-3 border-b border-border-col bg-card-deep">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-md bg-primary/10 border border-primary/25">
            <History className="w-3.5 h-3.5 text-primary" aria-hidden />
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-widest font-bold text-slate-500 font-mono">{"// recent_scans"}</div>
            <div className="text-[11px] font-mono text-slate-400">
              last 3 from remote database
            </div>
          </div>
        </div>
        <button
          onClick={load}
          disabled={loading}
          aria-label="Refresh history"
          className="p-2 rounded-lg border border-border-col bg-card text-slate-500 hover:text-primary hover:border-primary/30 transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed min-w-[40px] min-h-[40px] flex items-center justify-center"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} aria-hidden />
        </button>
      </header>

      <div className="p-4">
        {error && (
          <div className="px-4 py-3 rounded-lg border border-red-400/30 bg-red-400/8 text-[11px] font-mono text-red-300">
            {"// db error: "}{error}
          </div>
        )}

        {!error && loading && scans.length === 0 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                className="h-32 rounded-xl border border-border-col bg-card-deep/60 animate-pulse"
                aria-hidden
              />
            ))}
          </div>
        )}

        {!error && !loading && scans.length === 0 && (
          <div className="flex flex-col items-center justify-center py-8 gap-2 text-center">
            <Sparkles className="w-5 h-5 text-slate-600" aria-hidden />
            <p className="text-[11px] font-mono text-slate-500">{"// no scans saved yet — launch one above"}</p>
          </div>
        )}

        {!error && scans.length > 0 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            <AnimatePresence initial={false}>
              {scans.map((scan, idx) => {
                const verdict = verdictFromSummary(scan.ai_summary);
                const style = verdictStyles[verdict.tone];
                const Icon = style.icon;
                return (
                  <motion.button
                    key={scan.scan_id}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -6 }}
                    transition={{ duration: 0.18, delay: idx * 0.04 }}
                    onClick={() => onOpenScan(scan)}
                    aria-label={`Open scan for ${scan.target_url} from ${relativeTime(scan.scan_date)}`}
                    className={`group text-left p-4 rounded-xl border bg-card-deep/60 transition-all cursor-pointer flex flex-col gap-2.5 min-h-[136px] ${style.ring}`}
                  >
                    <div className="flex items-center gap-2 text-slate-500">
                      <Globe className="w-3 h-3 flex-shrink-0" aria-hidden />
                      <span className="text-[11px] font-mono font-semibold text-slate-200 truncate">
                        {hostname(scan.target_url)}
                      </span>
                    </div>

                    <p className="text-[10px] font-mono text-slate-400 line-clamp-3 leading-relaxed flex-1">
                      {scan.ai_summary
                        ? scan.ai_summary.replace(/^#.*$/gm, "").trim().slice(0, 140) + "…"
                        : "// summary unavailable"}
                    </p>

                    <div className="flex items-center justify-between">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[9px] font-bold uppercase tracking-wider font-mono border ${style.chip}`}
                      >
                        <Icon className="w-2.5 h-2.5" aria-hidden />
                        {verdict.label}
                      </span>
                      <span className="flex items-center gap-1 text-[10px] font-mono text-slate-500 group-hover:text-primary transition-colors">
                        {relativeTime(scan.scan_date)}
                        <ChevronRight className="w-3 h-3" aria-hidden />
                      </span>
                    </div>
                  </motion.button>
                );
              })}
            </AnimatePresence>
          </div>
        )}
      </div>
    </section>
  );
}
