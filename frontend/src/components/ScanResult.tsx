import type { RiskLevel, ScanResponse } from '../types/scan'
import { AIVerdictCard } from './AIVerdictCard'
import { EmailAuthSection } from './EmailAuthSection'
import { ThreatIntelSection } from './ThreatIntelSection'
import { WhoisSection } from './WhoisSection'

const GAUGE_R = 44
const GAUGE_CX = 54
const GAUGE_CY = 54
const GAUGE_CIRC = 2 * Math.PI * GAUGE_R

const RISK: Record<RiskLevel, { ring: string; text: string; badge: string; dot: string; label: string }> = {
  malicious: {
    ring: '#ef4444',
    text: 'text-red-400',
    badge: 'bg-red-500/15 text-red-400 border-red-500/30',
    dot: 'bg-red-500',
    label: 'MALICIOUS',
  },
  suspicious: {
    ring: '#f59e0b',
    text: 'text-amber-400',
    badge: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    dot: 'bg-amber-500',
    label: 'SUSPICIOUS',
  },
  clean: {
    ring: '#10b981',
    text: 'text-emerald-400',
    badge: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    dot: 'bg-emerald-500',
    label: 'CLEAN',
  },
  unknown: {
    ring: '#52525b',
    text: 'text-zinc-400',
    badge: 'bg-zinc-700 text-zinc-400 border-zinc-600',
    dot: 'bg-zinc-500',
    label: 'UNKNOWN',
  },
}

function RiskGauge({ score, level }: { score: number; level: RiskLevel }) {
  const c = RISK[level]
  const offset = GAUGE_CIRC - (score / 100) * GAUGE_CIRC
  return (
    <div className="relative flex-shrink-0 w-[108px] h-[108px]">
      <svg viewBox="0 0 108 108" className="w-full h-full -rotate-90">
        <circle cx={GAUGE_CX} cy={GAUGE_CY} r={GAUGE_R} fill="none" stroke="#27272a" strokeWidth="9" />
        <circle
          cx={GAUGE_CX} cy={GAUGE_CY} r={GAUGE_R}
          fill="none"
          stroke={c.ring}
          strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={GAUGE_CIRC}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 0.7s ease' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`text-3xl font-black tabular-nums leading-none ${c.text}`}>{score}</span>
        <span className="text-[10px] text-zinc-700 mt-0.5 font-medium">/ 100</span>
      </div>
    </div>
  )
}

function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + '…' : s
}

interface Props { result: ScanResponse }

export function ScanResult({ result }: Props) {
  const risk = result.risk_score
  const level: RiskLevel = risk?.level ?? 'unknown'
  const c = RISK[level]

  return (
    <div className="space-y-3">

      {/* ── Risk Score Card ─────────────────────────────────────────────────── */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
        <div className="p-5 flex gap-5 items-center">
          {risk && <RiskGauge score={risk.score} level={level} />}

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2.5 mb-3">
              <span className={`px-2.5 py-1 rounded-md text-[10px] font-bold tracking-widest border ${c.badge}`}>
                {c.label}
              </span>
              {risk && (
                <span className="text-xs text-zinc-600 tabular-nums">
                  {(risk.confidence * 100).toFixed(0)}% confidence
                </span>
              )}
            </div>
            <p className="text-sm font-mono text-zinc-300 break-all leading-snug mb-2">
              {truncate(result.target, 80)}
            </p>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[10px] font-semibold bg-zinc-800 text-zinc-500 px-1.5 py-0.5 rounded uppercase tracking-wider">
                {result.scan_type}
              </span>
              <span className="text-[10px] text-zinc-600">{formatDateTime(result.scanned_at)}</span>
              {result.duration_ms != null && (
                <span className="text-[10px] text-zinc-700">{(result.duration_ms / 1000).toFixed(1)}s</span>
              )}
            </div>
            <p className="text-[10px] font-mono text-zinc-700 mt-1">{result.scan_id}</p>
          </div>
        </div>

        {/* Contributing Factors */}
        {risk && risk.contributing_factors.length > 0 && (
          <div className="border-t border-zinc-800 px-5 py-4">
            <p className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest mb-3">
              Contributing Factors
            </p>
            <ul className="space-y-2">
              {risk.contributing_factors.map((factor, i) => (
                <li key={i} className="flex items-start gap-2.5 text-sm text-zinc-400">
                  <span className={`mt-1.5 h-1.5 w-1.5 rounded-full flex-shrink-0 ${c.dot}`} />
                  {factor}
                </li>
              ))}
            </ul>
          </div>
        )}

        {risk && risk.contributing_factors.length === 0 && (
          <div className="border-t border-zinc-800 px-5 py-4">
            <p className="text-sm text-zinc-600">No threat indicators found across active sources.</p>
          </div>
        )}
      </div>

      {/* ── AI Verdict ──────────────────────────────────────────────────────── */}
      {result.ai_verdict && <AIVerdictCard verdict={result.ai_verdict} />}

      {/* ── Threat Intelligence ─────────────────────────────────────────────── */}
      {result.threat_intel.length > 0 && (
        <ThreatIntelSection results={result.threat_intel} />
      )}

      {/* ── WHOIS + Email Auth ───────────────────────────────────────────────── */}
      {(result.whois ?? result.email_auth) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {result.whois && <WhoisSection whois={result.whois} />}
          {result.email_auth && <EmailAuthSection auth={result.email_auth} />}
        </div>
      )}

    </div>
  )
}
