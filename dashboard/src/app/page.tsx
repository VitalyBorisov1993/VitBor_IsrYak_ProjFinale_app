"use client";

import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import {
  Shield,
  Search,
  Terminal as TerminalIcon,
  Zap,
  AlertTriangle,
  CheckCircle,
  Loader2,
  ExternalLink,
  Settings2,
  FileCode,
  Globe2,
  MousePointer2,
  Clock,
  Eye,
  Crosshair,
  Activity,
  Sun,
  Moon,
  Copy,
  Check,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import {
  processLogLine,
  createParserState,
  emptyMeta,
  type SiteMeta,
  type PluginInfo,
} from "@/lib/parseLog";
import type { ScanRecord } from "@/lib/supabase";
import SiteMetaCard from "@/components/SiteMetaCard";
import PluginGallery from "@/components/PluginGallery";
import ScanHistory from "@/components/ScanHistory";
import HistoryDetailModal from "@/components/HistoryDetailModal";

const AnsiText = ({ text }: { text: string }) => {
  const parts = useMemo(() => {
    // If there are no ANSI escape codes, color based on standard log patterns
    if (!text.includes("\x1b[")) {
      let className = "text-slate-300";
      const cleanText = text.trim();
      if (/\[\+\]|SUCCESS|=== Starting|=== Scan Complete/i.test(cleanText)) {
        className = "text-green-400 font-semibold";
      } else if (/\[!\]|WARN|\[IGNORED\]|=== Site Metadata|--- HTTP Headers|^={3,}/i.test(cleanText)) {
        className = "text-amber-300 font-semibold";
      } else if (/\[!!!\]|ALERT|\[TRUE PRECURSOR DETECTED\]|CONFIRMED|exposed|EXPOSED|ACCESSIBLE/i.test(cleanText)) {
        className = "text-red-400 font-semibold";
      }
      return [{ text, className }];
    }

    const ansiRegex = /\x1b\[(\d+)m/g;
    let lastIndex = 0;
    const result: Array<{ text: string; className: string }> = [];
    let match: RegExpExecArray | null;
    let currentColorClass = "text-slate-300";

    const colorMap: Record<string, string> = {
      "91": "text-red-400 font-semibold",
      "92": "text-green-400 font-semibold",
      "93": "text-amber-300 font-semibold",
      "0": "text-slate-300",
    };

    while ((match = ansiRegex.exec(text)) !== null) {
      const before = text.substring(lastIndex, match.index);
      if (before) result.push({ text: before, className: currentColorClass });
      currentColorClass = colorMap[match[1]] || currentColorClass;
      lastIndex = ansiRegex.lastIndex;
    }

    const after = text.substring(lastIndex);
    if (after) result.push({ text: after, className: currentColorClass });

    return result;
  }, [text]);

  if (parts.length === 0) return <span>{text}</span>;

  return (
    <>
      {parts.map((p, i) => (
        <span key={i} className={p.className}>{p.text}</span>
      ))}
    </>
  );
};

const StatusBadge = ({ status }: { status: string }) => {
  const configs: Record<string, { icon: typeof Loader2; color: string; bg: string; label: string }> = {
    running:   { icon: Loader2,       color: "text-primary",   bg: "bg-primary/10 border-primary/25",   label: "Scanning" },
    completed: { icon: CheckCircle,   color: "text-green-400", bg: "bg-green-400/10 border-green-400/25", label: "Finished" },
    failed:    { icon: AlertTriangle, color: "text-red-400",   bg: "bg-red-400/10 border-red-400/25",   label: "Error" },
    aborted:   { icon: AlertTriangle, color: "text-amber-400", bg: "bg-amber-400/10 border-amber-400/25", label: "Aborted" },
    idle:      { icon: Zap,           color: "text-slate-500", bg: "bg-slate-500/10 border-slate-500/20", label: "Ready" },
  };

  const config = configs[status] || configs.idle;
  const Icon = config.icon;

  return (
    <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full border ${config.bg} ${config.color} text-xs font-bold tracking-wide`}>
      <Icon className={`w-3.5 h-3.5 ${status === "running" ? "animate-spin" : ""}`} />
      {config.label}
    </div>
  );
};

const SCAN_STEPS = [
  { num: 1, label: "Passive Recon",  short: "OSINT",   icon: Eye,       keyword: "Step 1:" },
  { num: 2, label: "WPScan Active",  short: "ACTIVE",  icon: Search,    keyword: "Step 2:" },
  { num: 3, label: "FFUF Brute",     short: "BRUTE",   icon: Crosshair, keyword: "Step 3:" },
  { num: 4, label: "Nuclei Verify",  short: "VERIFY",  icon: Activity,  keyword: "Step 4:" },
];

export default function Home() {
  const [url, setUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [status, setStatus] = useState<"idle" | "running" | "completed" | "failed" | "aborted">("idle");
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanTime, setScanTime] = useState(0);
  const [isDark, setIsDark] = useState<boolean>(true);
  const [themeReady, setThemeReady] = useState(false);

  const [mode, setMode] = useState<"stealth" | "aggressive">("stealth");
  const [masterList, setMasterList] = useState("");
  const [wordlist, setWordlist] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const [copiedLogs, setCopiedLogs] = useState(false);

  // NEW: parsed intel state
  const [siteMeta, setSiteMeta] = useState<SiteMeta>(emptyMeta());
  const [plugins, setPlugins] = useState<Map<string, PluginInfo>>(new Map());

  // NEW: history state
  const [historyRefreshKey, setHistoryRefreshKey] = useState(0);
  const [openedScan, setOpenedScan] = useState<ScanRecord | null>(null);

  const logEndRef = useRef<HTMLDivElement>(null);
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const logBufferRef = useRef<string[]>([]);
  const scanStartRef = useRef<number | null>(null);
  const parserStateRef = useRef(createParserState());
  const metaAccumRef = useRef<SiteMeta>(emptyMeta());
  const pluginsAccumRef = useRef<Map<string, PluginInfo>>(new Map());

  const statusRef = useRef(status);
  const scanIdRef = useRef(scanId);
  useEffect(() => { statusRef.current = status; }, [status]);
  useEffect(() => { scanIdRef.current = scanId; }, [scanId]);

  useEffect(() => {
    if (scrollContainerRef.current) {
      scrollContainerRef.current.scrollTop = scrollContainerRef.current.scrollHeight;
    }
  }, [logs]);

  useEffect(() => {
    const saved = localStorage.getItem("wpc-theme");
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setIsDark(saved !== "light");
    setThemeReady(true);
  }, []);

  useEffect(() => {
    if (!themeReady) return;
    if (isDark) {
      document.documentElement.removeAttribute("data-theme");
    } else {
      document.documentElement.setAttribute("data-theme", "light");
    }
  }, [isDark, themeReady]);

  useEffect(() => {
    let interval: ReturnType<typeof setInterval> | undefined;
    if (isScanning) {
      interval = setInterval(() => {
        if (scanStartRef.current !== null) {
          setScanTime(Math.floor((Date.now() - scanStartRef.current) / 1000));
        }
      }, 1000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isScanning]);

  const formatTime = (seconds: number) => {
    const m = Math.floor(seconds / 60).toString().padStart(2, "0");
    const s = (seconds % 60).toString().padStart(2, "0");
    return `${m}:${s}`;
  };

  const drainAndParse = useCallback(() => {
    if (logBufferRef.current.length === 0) return;
    const buffered = [...logBufferRef.current];
    logBufferRef.current = [];

    let m = metaAccumRef.current;
    let p = pluginsAccumRef.current;
    for (const line of buffered) {
      const r = processLogLine(line, parserStateRef.current, m, p);
      m = r.meta;
      p = r.plugins;
    }
    if (m !== metaAccumRef.current) {
      metaAccumRef.current = m;
      setSiteMeta(m);
    }
    if (p !== pluginsAccumRef.current) {
      pluginsAccumRef.current = p;
      setPlugins(p);
    }

    setLogs((prev) => [...prev.slice(-499 + buffered.length), ...buffered]);
  }, []);

  useEffect(() => {
    if (!isScanning) return;
    const interval = setInterval(drainAndParse, 150);
    return () => clearInterval(interval);
  }, [isScanning, drainAndParse]);

  const abortScan = async (e?: React.MouseEvent) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    setStatus("aborted");
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setIsScanning(false);
    const currentId = scanIdRef.current;
    if (currentId) {
      try {
        await fetch(`http://localhost:8000/abort/${currentId}`, { method: "POST" });
      } catch (err) {
        console.error("Failed to notify backend abort:", err);
      }
    }
  };

  const toggleTheme = () => {
    const next = !isDark;
    setIsDark(next);
    if (next) {
      document.documentElement.removeAttribute("data-theme");
      localStorage.setItem("wpc-theme", "dark");
    } else {
      document.documentElement.setAttribute("data-theme", "light");
      localStorage.setItem("wpc-theme", "light");
    }
  };

  const stopConnection = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    drainAndParse();
    setIsScanning(false);
    setHistoryRefreshKey((k) => k + 1);
  }, [drainAndParse]);

  const resetIntel = () => {
    parserStateRef.current = createParserState();
    metaAccumRef.current = emptyMeta();
    pluginsAccumRef.current = new Map();
    setSiteMeta(emptyMeta());
    setPlugins(new Map());
  };

  const startScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url || isScanning) return;

    setLogs([]);
    logBufferRef.current = [];
    resetIntel();
    setScanTime(0);
    scanStartRef.current = Date.now();
    setIsScanning(true);
    setStatus("running");

    let finalUrl = url.trim();
    if (!/^https?:\/\//i.test(finalUrl)) {
      finalUrl = "http://" + finalUrl;
      setUrl(finalUrl);
    }

    try {
      let query = `url=${encodeURIComponent(finalUrl)}&mode=${mode}`;
      if (masterList) query += `&master_list=${encodeURIComponent(masterList)}`;
      if (wordlist) query += `&wordlist=${encodeURIComponent(wordlist)}`;

      const eventSource = new EventSource(`http://localhost:8000/scan?${query}`);
      eventSourceRef.current = eventSource;

      eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === "log") {
          logBufferRef.current.push(data.msg);
        } else if (data.type === "status") {
          if (data.id) setScanId(data.id);
          if (data.code !== undefined) {
            setStatus(data.code === 0 ? "completed" : "failed");
            stopConnection();
          }
        }
      };

      eventSource.onerror = () => {
        if (statusRef.current !== "running") {
          stopConnection();
        }
      };
    } catch (err) {
      console.error(err);
      setStatus("failed");
      setIsScanning(false);
    }
  };

  const copyTerminal = async () => {
    if (logs.length === 0) return;
    const text = logs
      .map((l) => l.replace(/\x1b\[[0-9;]*m/g, ""))
      .join("\n");
    try {
      await navigator.clipboard.writeText(text);
      setCopiedLogs(true);
      setTimeout(() => setCopiedLogs(false), 1600);
    } catch (err) {
      console.error("Copy failed:", err);
    }
  };

  const loadHistoricalLog = (rawLog: string) => {
    if (isScanning) return;
    const lines = rawLog.split(/\r?\n/);
    resetIntel();
    let m = emptyMeta();
    let p: Map<string, PluginInfo> = new Map();
    const state = createParserState();
    for (const line of lines) {
      const r = processLogLine(line, state, m, p);
      m = r.meta;
      p = r.plugins;
    }
    parserStateRef.current = state;
    metaAccumRef.current = m;
    pluginsAccumRef.current = p;
    setSiteMeta(m);
    setPlugins(p);
    setLogs(lines);
    setStatus("completed");
  };

  const currentStep = useMemo(() => {
    for (let i = logs.length - 1; i >= 0; i--) {
      const line = logs[i];
      if (line.includes("Step 4:")) return 4;
      if (line.includes("Step 3:")) return 3;
      if (line.includes("Step 2:")) return 2;
      if (line.includes("Step 1:")) return 1;
    }
    return 0;
  }, [logs]);

  return (
    <div className="flex flex-col min-h-screen">
      {/* Background Orbs */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none -z-10" aria-hidden>
        <div className="absolute top-[-5%] left-[15%] w-[55%] h-[45%] bg-primary/5 rounded-full blur-[160px]" />
        <div className="absolute bottom-[5%] right-[-5%] w-[40%] h-[40%] bg-accent/5 rounded-full blur-[140px]" />
      </div>

      {/* Header */}
      <nav className={`flex items-center justify-between gap-3 px-4 sm:px-8 py-4 sm:py-5 border-b transition-all duration-500 ${
        isScanning
          ? "border-primary/20 bg-background/90 backdrop-blur-xl shadow-[0_1px_0_rgba(34,197,94,0.07)]"
          : "border-border-col glass"
      }`}>
        <div className="flex items-center gap-3 min-w-0">
          <div className={`p-2 rounded-xl border transition-all duration-300 flex-shrink-0 ${
            isScanning
              ? "bg-primary/20 border-primary/40 shadow-[0_0_18px_rgba(34,197,94,0.2)]"
              : "bg-primary/10 border-primary/20"
          }`}>
            <Shield className="w-5 h-5 text-primary" />
          </div>
          <div className="min-w-0">
            <span className="text-lg font-bold tracking-tight font-mono text-slate-100">WPC</span>
            <div className="text-[9px] uppercase tracking-[0.22em] text-slate-600 font-bold font-mono truncate">
              Webshell Precursor Correlator
            </div>
          </div>
        </div>

        <div className="flex items-center gap-1.5 sm:gap-3 flex-shrink-0">
          {status !== "idle" && (
            <div className={`hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-mono font-bold ${
              status === "running"
                ? "border-primary/20 bg-primary/5 text-primary"
                : "border-border-col bg-card text-slate-500"
            }`}>
              <Clock className={`w-3 h-3 ${status === "running" ? "animate-pulse" : ""}`} />
              {formatTime(scanTime)}
            </div>
          )}
          <button
            onClick={() => {
              if (isScanning) return;
              setLogs([]);
              logBufferRef.current = [];
              resetIntel();
              setStatus("idle");
            }}
            disabled={isScanning}
            className={`hidden md:inline text-[10px] font-bold uppercase tracking-widest px-3 py-1.5 rounded-lg transition-colors cursor-pointer font-mono ${
              isScanning
                ? "text-slate-700 cursor-not-allowed"
                : "text-slate-500 hover:text-slate-200 hover:bg-slate-800/50"
            }`}
          >
            Clear
          </button>
          <button
            onClick={() => setShowSettings(!showSettings)}
            aria-label="Toggle settings"
            className={`p-2 rounded-xl border transition-all cursor-pointer min-w-[40px] min-h-[40px] flex items-center justify-center ${
              showSettings
                ? "bg-primary/20 border-primary/40 text-primary"
                : "bg-card border-border-col text-slate-400 hover:text-slate-100 hover:border-slate-600"
            }`}
          >
            <Settings2 className="w-5 h-5" />
          </button>
          <button
            onClick={toggleTheme}
            aria-label="Toggle theme"
            suppressHydrationWarning
            className="p-2 rounded-xl border border-border-col bg-card text-slate-400 hover:text-slate-100 hover:border-slate-600 transition-all cursor-pointer min-w-[40px] min-h-[40px] flex items-center justify-center"
          >
            <span suppressHydrationWarning className="inline-flex">
              {themeReady ? (isDark ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />) : <Sun className="w-5 h-5 opacity-0" aria-hidden />}
            </span>
          </button>
          <StatusBadge status={status} />
        </div>
      </nav>

      {/* Main Content */}
      <main className="flex-1 max-w-6xl mx-auto w-full p-4 sm:p-6 lg:p-8 space-y-5">

        {/* Advanced Settings Panel */}
        <AnimatePresence>
          {showSettings && (
            <motion.section
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.18, ease: "easeOut" }}
              className="rounded-2xl border border-border-col bg-card overflow-hidden"
            >
              <div className="flex items-center gap-2 px-5 py-2.5 border-b border-border-col bg-card-deep">
                <div className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
                <div className="w-2.5 h-2.5 rounded-full bg-amber-500/60" />
                <div className="w-2.5 h-2.5 rounded-full bg-green-500/60" />
                <span className="text-[10px] text-slate-600 font-mono ml-2">scan_config</span>
              </div>
              <div className="p-5 sm:p-8 grid grid-cols-1 md:grid-cols-3 gap-6 sm:gap-8">
                <div className="space-y-3">
                  <label className="text-[10px] uppercase tracking-widest font-bold text-slate-500 font-mono">{"// scan_mode"}</label>
                  <div className="flex gap-2 p-1 bg-card-deep rounded-xl border border-border-col">
                    <button
                      onClick={() => { if (!isScanning) setMode("stealth"); }}
                      disabled={isScanning}
                      className={`flex-1 py-2 px-4 rounded-lg text-xs font-bold transition-all cursor-pointer min-h-[40px] ${
                        mode === "stealth" ? "bg-slate-700 text-slate-100" : "text-slate-500 hover:text-slate-300"
                      } ${isScanning ? "opacity-40 cursor-not-allowed" : ""}`}
                    >
                      Stealth
                    </button>
                    <button
                      onClick={() => { if (!isScanning) setMode("aggressive"); }}
                      disabled={isScanning}
                      className={`flex-1 py-2 px-4 rounded-lg text-xs font-bold transition-all cursor-pointer min-h-[40px] ${
                        mode === "aggressive" ? "bg-primary text-black" : "text-slate-500 hover:text-slate-300"
                      } ${isScanning ? "opacity-40 cursor-not-allowed" : ""}`}
                    >
                      Aggressive
                    </button>
                  </div>
                  <p className="text-[10px] text-slate-600 font-mono leading-relaxed">{"// Aggressive mode increases rate limits. May trigger WAF detection."}</p>
                </div>

                <div className="space-y-3">
                  <label className="text-[10px] uppercase tracking-widest font-bold text-slate-500 font-mono">{"// master_plugins_list"}</label>
                  <div className="relative">
                    <FileCode className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-600" />
                    <input
                      type="text"
                      placeholder="Default: master_plugins.txt"
                      className={`w-full bg-card-deep border border-border-col rounded-xl py-2.5 pl-9 pr-4 text-xs font-mono focus:outline-none focus:border-primary/40 focus:ring-1 focus:ring-primary/20 transition-all placeholder:text-slate-700 text-slate-200 min-h-[44px] ${isScanning ? "opacity-40 cursor-not-allowed" : ""}`}
                      value={masterList}
                      onChange={(e) => setMasterList(e.target.value)}
                      disabled={isScanning}
                    />
                  </div>
                  <p className="text-[10px] text-slate-600 font-mono">{"// Absolute path or local filename"}</p>
                </div>

                <div className="space-y-3">
                  <label className="text-[10px] uppercase tracking-widest font-bold text-slate-500 font-mono">{"// ffuf_wordlist"}</label>
                  <div className="relative">
                    <FileCode className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-600" />
                    <input
                      type="text"
                      placeholder="Default: ffuf_dict.txt"
                      className={`w-full bg-card-deep border border-border-col rounded-xl py-2.5 pl-9 pr-4 text-xs font-mono focus:outline-none focus:border-primary/40 focus:ring-1 focus:ring-primary/20 transition-all placeholder:text-slate-700 text-slate-200 min-h-[44px] ${isScanning ? "opacity-40 cursor-not-allowed" : ""}`}
                      value={wordlist}
                      onChange={(e) => setWordlist(e.target.value)}
                      disabled={isScanning}
                    />
                  </div>
                  <p className="text-[10px] text-slate-600 font-mono">{"// Custom dict for Step 3 FFUF brute-force"}</p>
                </div>
              </div>
            </motion.section>
          )}
        </AnimatePresence>

        {/* URL Input */}
        <section>
          <form onSubmit={startScan} className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1 group">
              <Globe2 className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600 group-focus-within:text-primary transition-colors" />
              <input
                type="text"
                placeholder="https://target-wordpress.com"
                className="w-full bg-card border border-border-col rounded-xl py-3.5 pl-11 pr-4 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/25 focus:border-primary/40 transition-all placeholder:text-slate-700 text-slate-100 min-h-[52px]"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
              />
            </div>
            {isScanning ? (
              <button
                type="button"
                onClick={(e) => abortScan(e)}
                className="px-6 py-3 bg-red-500 hover:bg-red-600 text-white font-bold rounded-xl transition-all shadow-lg shadow-red-500/20 flex items-center justify-center gap-2 text-sm cursor-pointer min-h-[52px]"
              >
                <AlertTriangle className="w-4 h-4" />
                Abort
              </button>
            ) : (
              <button
                type="submit"
                className="px-8 py-3 bg-primary hover:bg-primary/90 text-black font-bold rounded-xl transition-all shadow-lg shadow-primary/25 flex items-center justify-center gap-2 text-sm cursor-pointer neon-green min-h-[52px]"
              >
                <Zap className="w-4 h-4" />
                Launch Scan
              </button>
            )}
          </form>
        </section>

        {/* Step Progress */}
        <AnimatePresence>
          {status !== "idle" && (
            <motion.section
              initial={{ opacity: 0, y: -6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.18 }}
              className="grid grid-cols-2 sm:grid-cols-4 gap-2 sm:gap-3"
            >
              {SCAN_STEPS.map((step) => {
                const isDone = status === "completed" || currentStep > step.num;
                const isActive = isScanning && currentStep === step.num;
                const StepIcon = step.icon;
                return (
                  <div
                    key={step.num}
                    className={`flex items-center gap-2.5 sm:gap-3 p-3 sm:p-3.5 rounded-xl border transition-all duration-300 ${
                      isDone
                        ? "border-primary/25 bg-primary/5"
                        : isActive
                          ? "border-primary/35 bg-primary/8 shadow-[0_0_20px_rgba(34,197,94,0.07)]"
                          : "border-border-col bg-card"
                    }`}
                  >
                    <div className={`p-2 rounded-lg flex-shrink-0 transition-all ${
                      isDone || isActive ? "bg-primary/15" : "bg-slate-800/60"
                    }`}>
                      {isDone
                        ? <CheckCircle className="w-3.5 h-3.5 text-primary" />
                        : <StepIcon className={`w-3.5 h-3.5 ${isActive ? "text-primary animate-pulse" : "text-slate-600"}`} />
                      }
                    </div>
                    <div className="min-w-0">
                      <div className={`text-[9px] font-bold uppercase tracking-widest font-mono ${
                        isDone || isActive ? "text-primary" : "text-slate-600"
                      }`}>{step.short}</div>
                      <div className={`text-[11px] font-semibold truncate ${
                        isDone || isActive ? "text-slate-200" : "text-slate-600"
                      }`}>{step.label}</div>
                    </div>
                  </div>
                );
              })}
            </motion.section>
          )}
        </AnimatePresence>

        {/* Console & Sidebar */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 lg:gap-6 lg:items-start">

          {/* Terminal */}
          <div className="dark-zone lg:col-span-2 flex flex-col rounded-2xl border border-border-col overflow-hidden bg-[#040a14] min-h-[420px] lg:h-[560px]">
            <div className="flex items-center justify-between px-5 py-3.5 bg-[#080e1c] border-b border-[#1e293b] flex-shrink-0">
              <div className="flex items-center gap-3 min-w-0">
                <div className="flex gap-1.5 flex-shrink-0">
                  <div className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
                  <div className="w-2.5 h-2.5 rounded-full bg-amber-500/60" />
                  <div className="w-2.5 h-2.5 rounded-full bg-green-500/60" />
                </div>
                <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-slate-500 font-mono truncate">
                  <TerminalIcon className="w-3 h-3 flex-shrink-0" />
                  wpc ~ recon_console
                </div>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <div className="flex items-center gap-1.5 h-7 px-2 rounded bg-[#040a14] border border-[#1e293b] font-mono">
                  <span className={`text-[8px] ${status === "running" ? "text-primary" : "text-slate-700"}`}>●</span>
                  <span className="text-[10px] text-slate-600">{logs.length} lines</span>
                </div>
                <button
                  type="button"
                  onClick={copyTerminal}
                  disabled={logs.length === 0}
                  aria-label="Copy terminal output"
                  title={copiedLogs ? "Copied" : "Copy all output"}
                  className={`flex items-center gap-1.5 h-7 px-2.5 rounded border font-mono text-[10px] font-bold uppercase tracking-wider transition-colors cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed ${
                    copiedLogs
                      ? "border-primary/40 bg-primary/15 text-primary"
                      : "border-[#1e293b] bg-[#040a14] text-slate-500 hover:text-primary hover:border-primary/30"
                  }`}
                >
                  {copiedLogs ? (
                    <>
                      <Check className="w-3 h-3" aria-hidden />
                      copied
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" aria-hidden />
                      copy
                    </>
                  )}
                </button>
              </div>
            </div>

            <div
              ref={scrollContainerRef}
              className="flex-1 p-5 font-mono text-xs terminal-scroll overflow-y-auto terminal-bg"
            >
              {logs.length === 0 ? (
                <div className="h-full flex flex-col justify-center space-y-3 px-1">
                  <div className="space-y-1.5 text-[11px] font-mono">
                    <div className="text-primary/25">$ wpc --target &lt;url&gt; --mode stealth</div>
                    <div className="text-primary/16">$ Initializing MITRE T1505.003 scan engine...</div>
                    <div className="text-primary/10">$ Loading Wordfence intelligence database (60MB)...</div>
                    <div className="text-primary/6">$ Passive + Active + FFUF + Nuclei pipeline ready.</div>
                  </div>
                  <div className="flex items-center gap-1.5 text-primary/30 font-mono text-xs mt-2">
                    <span>$</span>
                    <span className="cursor-blink text-primary/50">█</span>
                  </div>
                </div>
              ) : (
                logs.map((log, i) => (
                  <div key={i} className="mb-0.5 flex gap-3 leading-relaxed">
                    <span className="text-slate-700 select-none w-5 text-right tabular-nums flex-shrink-0">{i + 1}</span>
                    <div className="break-all whitespace-pre-wrap flex-1 text-slate-300">
                      <AnsiText text={log} />
                    </div>
                  </div>
                ))
              )}
              <div ref={logEndRef} />
            </div>
          </div>

          {/* Sidebar */}
          <aside className="flex flex-col gap-3">
            <SiteMetaCard meta={siteMeta} />

            <div className="space-y-2.5">
              <h3 className="text-[9px] uppercase tracking-widest font-bold text-slate-600 font-mono px-1">{"// config"}</h3>
              <button
                onClick={() => setShowSettings(true)}
                className="w-full flex items-center justify-between p-3.5 rounded-xl border border-border-col bg-card hover:border-primary/30 hover:bg-primary/5 transition-all group cursor-pointer min-h-[60px]"
              >
                <div className="flex items-center gap-3 text-left">
                  <div className="p-2 bg-primary/10 rounded-lg group-hover:bg-primary/15 transition-all">
                    <Settings2 className="w-4 h-4 text-primary" />
                  </div>
                  <div>
                    <div className="text-[9px] text-slate-600 font-mono uppercase tracking-wider">engine_mode</div>
                    <div className="text-sm font-bold capitalize text-slate-200">{mode}</div>
                  </div>
                </div>
                <MousePointer2 className="w-3.5 h-3.5 text-slate-700 group-hover:text-primary transition-colors" />
              </button>

              <button
                onClick={() => setShowSettings(true)}
                className="w-full flex items-center justify-between p-3.5 rounded-xl border border-border-col bg-card hover:border-accent/30 hover:bg-accent/5 transition-all group cursor-pointer min-h-[60px]"
              >
                <div className="flex items-center gap-3 text-left">
                  <div className="p-2 bg-accent/10 rounded-lg group-hover:bg-accent/15 transition-all">
                    <FileCode className="w-4 h-4 text-accent" />
                  </div>
                  <div>
                    <div className="text-[9px] text-slate-600 font-mono uppercase tracking-wider">knowledge_db</div>
                    <div className="text-sm font-bold text-slate-200 truncate max-w-[140px]">
                      {masterList ? masterList.split("/").pop() : "160+ plugins"}
                    </div>
                  </div>
                </div>
                <MousePointer2 className="w-3.5 h-3.5 text-slate-700 group-hover:text-accent transition-colors" />
              </button>
            </div>

            {scanId && (
              <div className="rounded-xl p-4 border border-border-col bg-card flex flex-col gap-3 flex-shrink-0">
                <div className="flex items-center justify-between">
                  <span className="text-[9px] font-bold text-slate-600 uppercase tracking-widest font-mono">scan_id</span>
                  <span className="text-[10px] font-mono text-slate-400">{scanId.substring(0, 8)}…</span>
                </div>
                <a
                  href="https://supabase.com/dashboard/project/xvjfzfirzeluxgpvvmib/editor/scan_logs"
                  target="_blank"
                  rel="noreferrer"
                  className="w-full flex items-center justify-center gap-2 py-2.5 bg-primary/10 hover:bg-primary/20 text-primary rounded-lg transition-all text-[10px] font-bold font-mono border border-primary/20 hover:border-primary/40 cursor-pointer min-h-[40px]"
                >
                  Query Remote DB <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            )}

            {status === "completed" && (
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="rounded-xl p-4 border border-primary/20 bg-primary/5 flex items-center gap-3 flex-shrink-0"
              >
                <CheckCircle className="w-5 h-5 text-primary flex-shrink-0" />
                <div>
                  <div className="text-xs font-bold text-primary">Scan Complete</div>
                  <div className="text-[10px] text-slate-500 font-mono">{formatTime(scanTime)} elapsed</div>
                </div>
              </motion.div>
            )}

            <div className="rounded-xl p-4 border border-red-500/15 bg-red-500/5 flex-shrink-0">
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                <span className="text-[10px] font-bold uppercase tracking-widest text-red-400">T1505.003 Hunter</span>
              </div>
              <p className="text-[10px] text-slate-500 leading-relaxed font-mono">
                Passive OSINT → WPScan enumeration → FFUF webshell hunt → Nuclei signature verification. Rate-limited to avoid SOC detection.
              </p>
            </div>
          </aside>
        </div>

        {/* Plugin Gallery */}
        <PluginGallery plugins={plugins} />

        {/* Scan History */}
        <ScanHistory
          refreshKey={historyRefreshKey}
          onOpenScan={(scan) => setOpenedScan(scan)}
        />
      </main>

      <footer className="px-4 sm:px-8 py-6 border-t border-border-col flex flex-col items-center gap-2">
        <div className="text-slate-700 text-[9px] uppercase tracking-[0.25em] font-bold font-mono text-center">
          WPC — Webshell Precursor Correlator · Final Project 2026
        </div>
        <div className="flex flex-wrap justify-center gap-3 text-slate-800 text-[9px] font-bold uppercase tracking-wider font-mono">
          <span>WPScan</span>
          <span className="text-slate-800">·</span>
          <span>Nuclei</span>
          <span className="text-slate-800">·</span>
          <span>FFUF</span>
          <span className="text-slate-800">·</span>
          <span>Wordfence Intel</span>
        </div>
      </footer>

      <HistoryDetailModal
        scan={openedScan}
        onClose={() => setOpenedScan(null)}
        onLoadRawLog={loadHistoricalLog}
      />
    </div>
  );
}
