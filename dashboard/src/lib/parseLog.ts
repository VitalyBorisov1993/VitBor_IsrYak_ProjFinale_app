export type PluginSeverity = "vuln" | "minor-vuln" | "detected";

export interface PluginInfo {
  slug: string;
  version?: string;
  severity: PluginSeverity;
}

export interface SiteMeta {
  sha256?: string;
  statusCode?: number;
  headers: Record<string, string>;
  wpVersion?: string;
  wafs: string[];
}

export const emptyMeta = (): SiteMeta => ({ headers: {}, wafs: [] });

export interface ParserState {
  inMetaBlock: boolean;
  inHeadersSubBlock: boolean;
}

export const createParserState = (): ParserState => ({
  inMetaBlock: false,
  inHeadersSubBlock: false,
});

const ANSI_RE = /\x1b\[[0-9;]*m/g;
const TIMESTAMP_RE = /^\[\d{2}:\d{2}\]\s*/;

const stripDecorations = (line: string) =>
  line.replace(ANSI_RE, "").replace(TIMESTAMP_RE, "").trim();

const severityRank: Record<PluginSeverity, number> = {
  vuln: 3,
  "minor-vuln": 2,
  detected: 1,
};

const upgradePlugin = (
  plugins: Map<string, PluginInfo>,
  next: PluginInfo
): Map<string, PluginInfo> => {
  const existing = plugins.get(next.slug);
  if (existing && severityRank[existing.severity] > severityRank[next.severity]) {
    if (!existing.version && next.version) {
      const merged = new Map(plugins);
      merged.set(next.slug, { ...existing, version: next.version });
      return merged;
    }
    return plugins;
  }
  const merged = new Map(plugins);
  merged.set(next.slug, { ...existing, ...next });
  return merged;
};

export function processLogLine(
  rawLine: string,
  state: ParserState,
  meta: SiteMeta,
  plugins: Map<string, PluginInfo>
): { meta: SiteMeta; plugins: Map<string, PluginInfo> } {
  const line = stripDecorations(rawLine);
  if (!line) return { meta, plugins };

  if (/^={3,}\s*Site Metadata\s*={3,}$/i.test(line)) {
    state.inMetaBlock = true;
    state.inHeadersSubBlock = false;
    return { meta, plugins };
  }
  if (state.inMetaBlock && /^={5,}$/.test(line)) {
    state.inMetaBlock = false;
    state.inHeadersSubBlock = false;
    return { meta, plugins };
  }
  if (state.inMetaBlock) {
    if (/^---\s*HTTP Headers\s*---$/i.test(line)) {
      state.inHeadersSubBlock = true;
      return { meta, plugins };
    }
    if (!state.inHeadersSubBlock) {
      const sha = line.match(/^Body SHA-256\s*:\s*([a-f0-9]{40,})/i);
      if (sha) return { meta: { ...meta, sha256: sha[1] }, plugins };
      const status = line.match(/^Status Code\s*:\s*(\d+)/i);
      if (status) {
        return { meta: { ...meta, statusCode: Number.parseInt(status[1], 10) }, plugins };
      }
    } else {
      const hdr = line.match(/^([a-z0-9][a-z0-9\-_]*)\s*:\s*(.+)$/i);
      if (hdr && hdr[1].length < 40) {
        const next: SiteMeta = {
          ...meta,
          headers: { ...meta.headers, [hdr[1].toLowerCase()]: hdr[2].trim() },
        };
        return { meta: next, plugins };
      }
    }
    return { meta, plugins };
  }

  const wp = line.match(/WordPress core version detected (?:passively|actively?):\s*([\d.]+)/i);
  if (wp) return { meta: { ...meta, wpVersion: wp[1] }, plugins };

  const wafMatch = line.match(/(?:Protection detected|Active protections identified):\s*(.+)$/i);
  if (wafMatch) {
    const names = wafMatch[1]
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (names.length) {
      const merged = Array.from(new Set([...meta.wafs, ...names]));
      return { meta: { ...meta, wafs: merged }, plugins };
    }
  }

  const found = line.match(/Found\s+([a-z0-9][a-z0-9\-]+)\s+version\s+(\S+)/i);
  if (found) {
    const slug = found[1].toLowerCase();
    const version = found[2] === "Unknown" ? undefined : found[2];
    return { meta, plugins: upgradePlugin(plugins, { slug, version, severity: "detected" }) };
  }

  const precursor = line.match(
    /\[TRUE PRECURSOR DETECTED\]\s+(?:PLUGIN|THEME):([a-z0-9][a-z0-9\-]+)\s*\(v([^)]+)\)/i
  );
  if (precursor) {
    return {
      meta,
      plugins: upgradePlugin(plugins, {
        slug: precursor[1].toLowerCase(),
        version: precursor[2],
        severity: "vuln",
      }),
    };
  }

  const ignored = line.match(
    /\[IGNORED\]\s+([a-z0-9][a-z0-9\-]+)\s*\(v([^)]+)\)\s+has general bugs/i
  );
  if (ignored) {
    return {
      meta,
      plugins: upgradePlugin(plugins, {
        slug: ignored[1].toLowerCase(),
        version: ignored[2],
        severity: "minor-vuln",
      }),
    };
  }

  const passiveVer = line.match(/Using passive version for\s+([a-z0-9][a-z0-9\-]+):\s*([\d.]+)/i);
  if (passiveVer) {
    return {
      meta,
      plugins: upgradePlugin(plugins, {
        slug: passiveVer[1].toLowerCase(),
        version: passiveVer[2],
        severity: "detected",
      }),
    };
  }

  return { meta, plugins };
}

const HEADERS_OF_INTEREST = [
  "server",
  "x-powered-by",
  "content-type",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
  "x-xss-protection",
  "cache-control",
];

export const pickInterestingHeaders = (
  headers: Record<string, string>
): Array<[string, string]> => {
  const out: Array<[string, string]> = [];
  for (const key of HEADERS_OF_INTEREST) {
    if (headers[key]) out.push([key, headers[key]]);
  }
  return out;
};
