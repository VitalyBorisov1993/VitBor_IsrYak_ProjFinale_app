"use client";

import { motion, AnimatePresence } from "framer-motion";
import {
  Fingerprint,
  ShieldAlert,
  Server,
  ChevronDown,
  Wifi,
} from "lucide-react";
import { useState } from "react";
import type { SiteMeta } from "@/lib/parseLog";
import { pickInterestingHeaders } from "@/lib/parseLog";

interface Props {
  meta: SiteMeta;
}

const isEmpty = (m: SiteMeta) =>
  !m.sha256 && !m.statusCode && !m.wpVersion && m.wafs.length === 0 && Object.keys(m.headers).length === 0;

export default function SiteMetaCard({ meta }: Props) {
  const [open, setOpen] = useState(false);
  if (isEmpty(meta)) return null;

  const headers = pickInterestingHeaders(meta.headers);
  const statusColor =
    !meta.statusCode
      ? "text-slate-400"
      : meta.statusCode >= 500
        ? "text-red-400"
        : meta.statusCode >= 400
          ? "text-amber-300"
          : "text-primary";

  return (
    <motion.section
      initial={{ opacity: 0, y: -6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.22 }}
      className="rounded-2xl border border-border-col bg-card overflow-hidden"
      aria-label="Target intelligence"
    >
      <header className="flex items-center justify-between gap-2 px-4 py-2.5 border-b border-border-col bg-card-deep">
        <div className="flex items-center gap-2">
          <Fingerprint className="w-3.5 h-3.5 text-accent" aria-hidden />
          <span className="text-[10px] font-bold uppercase tracking-widest text-slate-500 font-mono">{"// site_intel"}</span>
        </div>
        {meta.statusCode !== undefined && (
          <span className={`text-[10px] font-mono font-bold ${statusColor}`}>
            HTTP {meta.statusCode}
          </span>
        )}
      </header>

      <div className="p-4 space-y-3.5">
        {meta.wpVersion && (
          <div className="flex items-center justify-between gap-3 px-3 py-2 rounded-lg bg-card-deep/60 border border-border-col">
            <div className="flex items-center gap-2 min-w-0">
              <Server className="w-3.5 h-3.5 text-primary flex-shrink-0" aria-hidden />
              <span className="text-[10px] uppercase tracking-wider font-mono text-slate-500">
                wp_core
              </span>
            </div>
            <span className="text-xs font-mono font-bold text-slate-200 tabular-nums">
              v{meta.wpVersion}
            </span>
          </div>
        )}

        {meta.wafs.length > 0 && (
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-3 h-3 text-amber-300" aria-hidden />
              <span className="text-[10px] uppercase tracking-wider font-mono text-slate-500">
                protections
              </span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {meta.wafs.map((waf) => (
                <span
                  key={waf}
                  className="px-2 py-0.5 rounded-md border border-amber-300/30 bg-amber-300/10 text-[10px] font-mono font-bold text-amber-200"
                >
                  {waf}
                </span>
              ))}
            </div>
          </div>
        )}

        {meta.sha256 && (
          <div className="space-y-1">
            <span className="text-[10px] uppercase tracking-wider font-mono text-slate-500">{"// body_sha256"}</span>
            <div
              title={meta.sha256}
              className="px-2.5 py-1.5 rounded-md bg-card-deep border border-border-col text-[10px] font-mono text-slate-300 break-all leading-relaxed select-all"
            >
              {meta.sha256.slice(0, 16)}…{meta.sha256.slice(-12)}
            </div>
          </div>
        )}

        {headers.length > 0 && (
          <div>
            <button
              onClick={() => setOpen((p) => !p)}
              aria-expanded={open}
              className="flex items-center gap-2 w-full text-left cursor-pointer group"
            >
              <Wifi className="w-3 h-3 text-slate-500 group-hover:text-primary transition-colors" aria-hidden />
              <span className="text-[10px] uppercase tracking-wider font-mono text-slate-500 group-hover:text-slate-200 transition-colors">
                headers · {headers.length}
              </span>
              <ChevronDown
                className={`ml-auto w-3 h-3 text-slate-600 transition-transform duration-200 ${open ? "rotate-180" : ""}`}
                aria-hidden
              />
            </button>
            <AnimatePresence initial={false}>
              {open && (
                <motion.ul
                  key="headers-list"
                  initial={{ opacity: 0, y: -4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -4 }}
                  transition={{ duration: 0.16 }}
                  className="mt-2 space-y-1 font-mono text-[10px]"
                >
                  {headers.map(([k, v]) => (
                    <li key={k} className="flex gap-2">
                      <span className="text-accent flex-shrink-0">{k}</span>
                      <span className="text-slate-400 break-all">{v}</span>
                    </li>
                  ))}
                </motion.ul>
              )}
            </AnimatePresence>
          </div>
        )}
      </div>
    </motion.section>
  );
}
