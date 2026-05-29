import type { ThreatIntelResult } from '../types/scan'

interface Props {
  results: ThreatIntelResult[]
}

function formatSource(source: string): string {
  if (source.startsWith('virustotal_')) {
    const suffix = source.replace('virustotal_', '')
    return `VirusTotal · ${suffix.charAt(0).toUpperCase() + suffix.slice(1)}`
  }
  if (source === 'abuseipdb') return 'AbuseIPDB'
  return source.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function StatusDot({ result }: { result: ThreatIntelResult }) {
  if (result.error) return <span className="h-2 w-2 rounded-full bg-zinc-700 flex-shrink-0 mt-1" />
  if (result.detected === true)
    return <span className="h-2 w-2 rounded-full bg-red-500 flex-shrink-0 mt-1 shadow-[0_0_6px_#ef4444]" />
  if (result.detected === false)
    return <span className="h-2 w-2 rounded-full bg-emerald-500 flex-shrink-0 mt-1" />
  return <span className="h-2 w-2 rounded-full bg-zinc-700 flex-shrink-0 mt-1" />
}

function StatusBadge({ result }: { result: ThreatIntelResult }) {
  if (result.error) {
    return (
      <span className="text-[10px] font-semibold text-zinc-600 uppercase tracking-wider">
        {result.error.replace(/_/g, ' ')}
      </span>
    )
  }
  if (result.detected === true) {
    return (
      <span className="text-[10px] font-bold text-red-400 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded uppercase tracking-wider">
        Detected
      </span>
    )
  }
  if (result.detected === false) {
    return (
      <span className="text-[10px] font-bold text-emerald-600 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded uppercase tracking-wider">
        Clean
      </span>
    )
  }
  return null
}

function VTBar({ malicious, suspicious, total }: { malicious: number; suspicious: number; total: number }) {
  if (total === 0) return null
  const mW = (malicious / total) * 100
  const sW = (suspicious / total) * 100
  return (
    <div className="flex items-center gap-2.5">
      <div className="w-24 h-1.5 bg-zinc-800 rounded-full overflow-hidden flex">
        <div className="h-full bg-red-500 rounded-full" style={{ width: `${mW}%` }} />
        <div className="h-full bg-amber-500 rounded-full" style={{ width: `${sW}%` }} />
      </div>
      <span className="text-xs text-zinc-600 tabular-nums">
        {malicious + suspicious}/{total} flagged
      </span>
    </div>
  )
}

function AbuseBar({ confidence }: { confidence: number }) {
  const color = confidence >= 80 ? '#ef4444' : confidence >= 25 ? '#f59e0b' : confidence >= 5 ? '#f59e0b80' : '#10b981'
  return (
    <div className="flex items-center gap-2.5">
      <div className="w-24 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${confidence}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs text-zinc-600 tabular-nums">{confidence}% confidence</span>
    </div>
  )
}

function SourceDetails({ result }: { result: ThreatIntelResult }) {
  if (!result.raw_data || result.error) return null
  const d = result.raw_data

  if (result.source.startsWith('virustotal')) {
    const malicious = typeof d.malicious === 'number' ? d.malicious : 0
    const suspicious = typeof d.suspicious === 'number' ? d.suspicious : 0
    const total = typeof d.total_engines === 'number' ? d.total_engines : 0
    const rep = typeof d.reputation === 'number' ? d.reputation : null
    if (total === 0 && rep === null) return null
    return (
      <div className="mt-1.5 space-y-1.5">
        {total > 0 && <VTBar malicious={malicious} suspicious={suspicious} total={total} />}
        {rep !== null && (
          <span className={`text-xs tabular-nums ${rep < -10 ? 'text-amber-600' : 'text-zinc-700'}`}>
            community rep {rep > 0 ? '+' : ''}{rep}
          </span>
        )}
      </div>
    )
  }

  if (result.source === 'abuseipdb') {
    const confidence = typeof d.abuse_confidence_score === 'number' ? d.abuse_confidence_score : 0
    const reports = typeof d.total_reports === 'number' ? d.total_reports : 0
    const isTor = Boolean(d.is_tor)
    const country = typeof d.country_code === 'string' ? d.country_code : null
    const isp = typeof d.isp === 'string' ? d.isp : null
    return (
      <div className="mt-1.5 space-y-1.5">
        <AbuseBar confidence={confidence} />
        <div className="flex gap-2 flex-wrap items-center">
          <span className="text-[10px] text-zinc-600">{reports} reports</span>
          {isTor && (
            <span className="text-[10px] font-bold text-amber-500 bg-amber-500/10 border border-amber-500/20 px-1.5 py-0.5 rounded uppercase tracking-wider">
              TOR
            </span>
          )}
          {country && <span className="text-[10px] text-zinc-600">{country}</span>}
          {isp && <span className="text-[10px] text-zinc-700 truncate max-w-[160px]">{isp}</span>}
        </div>
      </div>
    )
  }
  return null
}

export function ThreatIntelSection({ results }: Props) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
      <div className="px-4 py-3 border-b border-zinc-800">
        <h3 className="text-[10px] font-semibold text-zinc-500 uppercase tracking-widest">
          Threat Intelligence
        </h3>
      </div>
      <div className="divide-y divide-zinc-800/50">
        {results.map((result, i) => (
          <div key={i} className="px-4 py-3.5 flex items-start justify-between gap-4">
            <div className="flex items-start gap-2.5 min-w-0">
              <StatusDot result={result} />
              <div className="min-w-0">
                <p className="text-sm font-medium text-zinc-300 leading-tight">
                  {formatSource(result.source)}
                </p>
                <SourceDetails result={result} />
              </div>
            </div>
            <div className="flex-shrink-0">
              <StatusBadge result={result} />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
