"use client";

import { motion, AnimatePresence } from "framer-motion";
import { Puzzle, ShieldOff, ShieldCheck, ShieldQuestion } from "lucide-react";
import { useMemo, useState } from "react";
import type { PluginInfo, PluginSeverity } from "@/lib/parseLog";

interface Props {
  plugins: Map<string, PluginInfo>;
}

type Filter = "all" | PluginSeverity;

const severityMeta: Record<
  PluginSeverity,
  { label: string; ring: string; badge: string; text: string; Icon: typeof ShieldOff }
> = {
  vuln: {
    label: "vulnerable",
    ring: "border-red-400/35 bg-red-400/8 hover:bg-red-400/12",
    badge: "bg-red-500 text-white",
    text: "text-red-300",
    Icon: ShieldOff,
  },
  "minor-vuln": {
    label: "minor",
    ring: "border-amber-300/30 bg-amber-300/8 hover:bg-amber-300/12",
    badge: "bg-amber-400 text-black",
    text: "text-amber-200",
    Icon: ShieldQuestion,
  },
  detected: {
    label: "detected",
    ring: "border-accent/25 bg-accent/8 hover:bg-accent/12",
    badge: "bg-accent text-black",
    text: "text-accent",
    Icon: ShieldCheck,
  },
};

export default function PluginGallery({ plugins }: Props) {
  const [filter, setFilter] = useState<Filter>("all");

  const list = useMemo(() => Array.from(plugins.values()), [plugins]);

  const counts = useMemo(() => {
    const c = { all: list.length, vuln: 0, "minor-vuln": 0, detected: 0 } as Record<Filter, number>;
    for (const p of list) c[p.severity] += 1;
    return c;
  }, [list]);

  const visible = useMemo(() => {
    const sorted = [...list].sort((a, b) => {
      const order: Record<PluginSeverity, number> = { vuln: 0, "minor-vuln": 1, detected: 2 };
      const diff = order[a.severity] - order[b.severity];
      return diff !== 0 ? diff : a.slug.localeCompare(b.slug);
    });
    return filter === "all" ? sorted : sorted.filter((p) => p.severity === filter);
  }, [list, filter]);

  if (list.length === 0) return null;

  const filters: Array<{ id: Filter; label: string; count: number }> = [
    { id: "all", label: "all", count: counts.all },
    { id: "vuln", label: "vulnerable", count: counts.vuln },
    { id: "minor-vuln", label: "minor", count: counts["minor-vuln"] },
    { id: "detected", label: "detected", count: counts.detected },
  ];

  return (
    <section
      className="rounded-2xl border border-border-col bg-card overflow-hidden"
      aria-label="Detected plugins"
    >
      <header className="flex items-center justify-between gap-3 px-5 py-3 border-b border-border-col bg-card-deep flex-wrap">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-md bg-accent/10 border border-accent/25">
            <Puzzle className="w-3.5 h-3.5 text-accent" aria-hidden />
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-widest font-bold text-slate-500 font-mono">{"// plugin_intel"}</div>
            <div className="text-[11px] font-mono text-slate-300">
              <span className="text-slate-200 font-bold tabular-nums">{counts.all}</span> detected
              {counts.vuln > 0 && (
                <>
                  {" · "}
                  <span className="text-red-400 font-bold tabular-nums">{counts.vuln}</span> vulnerable
                </>
              )}
              {counts["minor-vuln"] > 0 && (
                <>
                  {" · "}
                  <span className="text-amber-300 font-bold tabular-nums">{counts["minor-vuln"]}</span> minor
                </>
              )}
            </div>
          </div>
        </div>

        <div
          role="tablist"
          aria-label="Filter by severity"
          className="flex gap-1 p-1 rounded-lg bg-card border border-border-col"
        >
          {filters.map((f) => {
            const active = filter === f.id;
            return (
              <button
                key={f.id}
                role="tab"
                aria-selected={active}
                disabled={f.count === 0 && f.id !== "all"}
                onClick={() => setFilter(f.id)}
                className={`px-2.5 py-1.5 rounded-md text-[10px] font-bold uppercase tracking-wider font-mono transition-colors cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed min-h-[32px] ${
                  active
                    ? "bg-slate-700 text-slate-100"
                    : "text-slate-500 hover:text-slate-200"
                }`}
              >
                {f.label}
                <span className="ml-1 opacity-60 tabular-nums">{f.count}</span>
              </button>
            );
          })}
        </div>
      </header>

      <div className="p-4">
        <ul className="flex flex-wrap gap-2">
          <AnimatePresence initial={false} mode="popLayout">
            {visible.map((p, idx) => {
              const meta = severityMeta[p.severity];
              const Icon = meta.Icon;
              return (
                <motion.li
                  key={p.slug}
                  layout
                  initial={{ opacity: 0, scale: 0.92 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.92 }}
                  transition={{ duration: 0.18, delay: Math.min(idx * 0.018, 0.4) }}
                  className={`flex items-center gap-2 px-2.5 py-1.5 rounded-lg border ${meta.ring} transition-colors min-h-[36px]`}
                  title={`${p.slug}${p.version ? ` v${p.version}` : ""} — ${meta.label}`}
                >
                  <Icon className={`w-3 h-3 flex-shrink-0 ${meta.text}`} aria-hidden />
                  <span className="text-[11px] font-mono font-semibold text-slate-200 break-all">
                    {p.slug}
                  </span>
                  {p.version && (
                    <span className="text-[10px] font-mono text-slate-500 tabular-nums">
                      v{p.version}
                    </span>
                  )}
                  {p.severity === "vuln" && (
                    <span className={`text-[8px] font-mono font-bold px-1 py-0.5 rounded ${meta.badge}`}>
                      !
                    </span>
                  )}
                </motion.li>
              );
            })}
          </AnimatePresence>
        </ul>
        {visible.length === 0 && (
          <p className="text-[11px] font-mono text-slate-600 text-center py-3">{"// no plugins in this category"}</p>
        )}
      </div>
    </section>
  );
}
