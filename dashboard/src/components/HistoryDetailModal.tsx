"use client";

import { motion, AnimatePresence } from "framer-motion";
import {
  X,
  Globe,
  Clock,
  Terminal as TerminalIcon,
  Loader2,
  Sparkles,
  Copy,
  Check,
} from "lucide-react";
import { useEffect, useState } from "react";
import { fetchScanDetail, type ScanRecord, type ScanDetail } from "@/lib/supabase";

interface Props {
  scan: ScanRecord | null;
  onClose: () => void;
  onLoadRawLog: (log: string) => void;
}

const formatDate = (iso: string): string => {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
};

export default function HistoryDetailModal({ scan, onClose, onLoadRawLog }: Props) {
  const [detail, setDetail] = useState<ScanDetail | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!scan) return;
    let cancelled = false;
    fetchScanDetail(scan.scan_id)
      .then((d) => {
        if (!cancelled) setDetail(d);
      })
      .catch(() => {
        /* leave detail as-is; render falls back to scan.ai_summary */
      });
    return () => {
      cancelled = true;
    };
  }, [scan]);

  const matchedDetail = scan && detail && detail.scan_id === scan.scan_id ? detail : null;
  const loading = !!scan && matchedDetail === null;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    if (scan) window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [scan, onClose]);

  const handleCopy = async () => {
    const text = matchedDetail?.ai_summary ?? scan?.ai_summary ?? "";
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      /* swallow */
    }
  };

  const summary = matchedDetail?.ai_summary ?? scan?.ai_summary ?? null;
  const hasLog = !!matchedDetail?.raw_log;

  return (
    <AnimatePresence>
      {scan && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.18 }}
          className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6"
          aria-modal="true"
          role="dialog"
          aria-labelledby="history-modal-title"
        >
          <button
            onClick={onClose}
            aria-label="Close modal"
            className="absolute inset-0 bg-black/70 backdrop-blur-sm cursor-pointer"
          />

          <motion.div
            initial={{ opacity: 0, scale: 0.96, y: 12 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96, y: 12 }}
            transition={{ duration: 0.2 }}
            className="relative w-full max-w-3xl max-h-[85vh] flex flex-col rounded-2xl border border-border-col bg-card shadow-[0_30px_80px_rgba(0,0,0,0.55)] overflow-hidden"
          >
            <header className="flex items-start justify-between gap-4 px-6 py-4 border-b border-border-col bg-card-deep flex-shrink-0">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 text-[10px] uppercase tracking-widest font-bold text-primary font-mono mb-1.5">
                  <Sparkles className="w-3 h-3" aria-hidden />{"// ai_executive_summary"}</div>
                <h2 id="history-modal-title" className="flex items-center gap-2 text-sm font-mono font-bold text-slate-100 truncate">
                  <Globe className="w-3.5 h-3.5 text-accent flex-shrink-0" aria-hidden />
                  <span className="truncate">{scan.target_url}</span>
                </h2>
                <div className="flex items-center gap-3 mt-1.5 text-[10px] font-mono text-slate-500">
                  <span className="flex items-center gap-1">
                    <Clock className="w-2.5 h-2.5" aria-hidden />
                    {formatDate(scan.scan_date)}
                  </span>
                  <span className="truncate">id: {scan.scan_id.slice(0, 8)}…</span>
                </div>
              </div>
              <button
                onClick={onClose}
                aria-label="Close"
                className="p-2 rounded-lg border border-border-col bg-card text-slate-400 hover:text-slate-100 hover:border-slate-500 transition-colors cursor-pointer min-w-[40px] min-h-[40px] flex items-center justify-center flex-shrink-0"
              >
                <X className="w-4 h-4" aria-hidden />
              </button>
            </header>

            <div className="flex-1 overflow-y-auto terminal-scroll p-6 space-y-4">
              {loading && !summary && (
                <div className="flex flex-col items-center justify-center py-12 gap-3">
                  <Loader2 className="w-5 h-5 text-primary animate-spin" aria-hidden />
                  <p className="text-[11px] font-mono text-slate-500">{"// loading summary…"}</p>
                </div>
              )}

              {summary && (
                <div className="rounded-xl border border-border-col bg-card-deep/60 p-5">
                  <pre className="text-[12px] font-mono leading-relaxed text-slate-300 whitespace-pre-wrap break-words">
                    {summary}
                  </pre>
                </div>
              )}

              {!loading && !summary && (
                <div className="px-5 py-6 rounded-xl border border-border-col bg-card-deep/60 text-center">
                  <p className="text-[11px] font-mono text-slate-500">{"// no ai summary attached to this scan"}</p>
                </div>
              )}
            </div>

            <footer className="flex items-center justify-end gap-2 px-6 py-3.5 border-t border-border-col bg-card-deep flex-shrink-0 flex-wrap">
              <button
                onClick={handleCopy}
                disabled={!summary}
                className="flex items-center gap-2 px-3 py-2 rounded-lg border border-border-col bg-card text-slate-400 hover:text-slate-100 hover:border-slate-500 transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed min-h-[40px] text-[11px] font-mono font-bold"
              >
                {copied ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-primary" aria-hidden />
                    copied
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" aria-hidden />
                    copy summary
                  </>
                )}
              </button>
              <button
                onClick={() => {
                  if (matchedDetail?.raw_log) {
                    onLoadRawLog(matchedDetail.raw_log);
                    onClose();
                  }
                }}
                disabled={!hasLog}
                className="flex items-center gap-2 px-3 py-2 rounded-lg border border-primary/30 bg-primary/10 text-primary hover:bg-primary/20 hover:border-primary/55 transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed min-h-[40px] text-[11px] font-mono font-bold"
              >
                <TerminalIcon className="w-3.5 h-3.5" aria-hidden />
                load raw log
              </button>
            </footer>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
