import { useState } from 'react'
import { downloadPdfReport } from '../api/client'
import type { RiskLevel, ScanResponse } from '../types/scan'
import { AIVerdictCard } from './AIVerdictCard'
import { EmailAuthSection } from './EmailAuthSection'
import { KeywordSection } from './KeywordSection'
import { MITRESection } from './MITRESection'
import { ThreatIntelSection } from './ThreatIntelSection'
import { TyposquattingSection } from './TyposquattingSection'
import { URLAnalysisSection } from './URLAnalysisSection'
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
  const [downloading, setDownloading] = useState(false)
  const [downloadError, setDownloadError] = useState<string | null>(null)

  const risk = result.risk_score
  const level: RiskLevel = risk?.level ?? 'unknown'
  const c = RISK[level]

  async function handleDownloadPdf() {
    setDownloading(true)
    setDownloadError(null)
    try {
      await downloadPdfReport(result.scan_id)
    } catch (err) {
      setDownloadError(err instanceof Error ? err.message : 'Download failed')
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div className="space-y-3">

      {/* ── Risk Score Card ─────────────────────────────────────────────────── */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
        <div className="p-5 flex gap-5 items-center">
          {risk && <RiskGauge score={risk.score} level={level} />}

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2.5 mb-3 flex-wrap">
              <span className={`px-2.5 py-1 rounded-md text-[10px] font-bold tracking-widest border ${c.badge}`}>
                {c.label}
              </span>
              {risk && (
                <span className="text-xs text-zinc-600 tabular-nums">
                  {(risk.confidence * 100).toFixed(0)}% confidence
                </span>
              )}
              {/* PDF Export Button */}
              <button
                onClick={handleDownloadPdf}
                disabled={downloading}
                className="ml-auto flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[10px] font-semibold
                           bg-zinc-800 text-zinc-400 border border-zinc-700
                           hover:bg-zinc-700 hover:text-zinc-200 hover:border-zinc-600
                           disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {downloading ? (
                  <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                ) : (
                  <svg className="h-3 w-3" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clipRule="evenodd" />
                  </svg>
                )}
                {downloading ? 'Generating…' : 'PDF Report'}
              </button>
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

            {downloadError && (
              <p className="text-[10px] text-red-400 mt-1">{downloadError}</p>
            )}
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

      {/* ── MITRE ATT&CK ────────────────────────────────────────────────────── */}
      {result.mitre_tactics && result.mitre_tactics.techniques.length > 0 && (
        <MITRESection mitre={result.mitre_tactics} />
      )}

      {/* ── AI Verdict ──────────────────────────────────────────────────────── */}
      {result.ai_verdict && <AIVerdictCard verdict={result.ai_verdict} />}

      {/* ── Threat Intelligence ─────────────────────────────────────────────── */}
      {result.threat_intel.length > 0 && (
        <ThreatIntelSection results={result.threat_intel} />
      )}

      {/* ── Typosquatting + URL Analysis ────────────────────────────────────── */}
      {(result.typosquatting ?? result.url_analysis) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {result.typosquatting && (
            <TyposquattingSection typo={result.typosquatting} />
          )}
          {result.url_analysis && result.url_analysis.analyzed_urls.length > 0 && (
            <URLAnalysisSection analysis={result.url_analysis} />
          )}
        </div>
      )}

      {/* ── Keyword Detection ───────────────────────────────────────────────── */}
      {result.keywords && result.keywords.matches.length > 0 && (
        <KeywordSection keywords={result.keywords} />
      )}

      {/* ── WHOIS + Email Auth ───────────────────────────────────────────────── */}
      {(result.whois ?? result.email_auth) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {result.whois && <WhoisSection whois={result.whois} />}
          {result.email_auth && <EmailAuthSection auth={result.email_auth} />}
        </div>
      )}

      {/* ── Email Routing Chain ─────────────────────────────────────────────── */}
      {result.email_headers && result.email_headers.hop_count > 0 && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
          <div className="px-5 py-3 border-b border-zinc-800 flex items-center justify-between">
            <span className="text-[10px] font-semibold text-zinc-500 uppercase tracking-widest">
              Email Routing Chain
            </span>
            <span className="text-[10px] text-zinc-600">
              {result.email_headers.hop_count} hop{result.email_headers.hop_count !== 1 ? 's' : ''}
            </span>
          </div>
          <div className="px-5 py-4 space-y-2">
            {result.email_headers.originating_ip && (
              <div className="flex items-center gap-2 text-xs">
                <span className="text-zinc-600 w-28 flex-shrink-0">Originating IP</span>
                <span className="font-mono text-amber-400">{result.email_headers.originating_ip}</span>
              </div>
            )}
            {result.email_headers.x_mailer && (
              <div className="flex items-center gap-2 text-xs">
                <span className="text-zinc-600 w-28 flex-shrink-0">X-Mailer</span>
                <span className={`font-mono ${result.email_headers.suspicious_mailer ? 'text-red-400' : 'text-zinc-400'}`}>
                  {result.email_headers.x_mailer}
                  {result.email_headers.suspicious_mailer && (
                    <span className="ml-2 text-[9px] font-bold px-1 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400 uppercase">
                      Suspicious
                    </span>
                  )}
                </span>
              </div>
            )}
            <div className="mt-2 space-y-1">
              {result.email_headers.hops.slice(0, 6).map((hop, i) => (
                <div key={i} className="flex items-start gap-2 text-[11px]">
                  <span className="text-zinc-700 font-mono w-4 flex-shrink-0">{i + 1}</span>
                  <span className="text-zinc-500">
                    {hop.from_host && <span>from <span className="text-zinc-400 font-mono">{hop.from_host}</span> </span>}
                    {hop.by_host && <span>→ <span className="text-zinc-400 font-mono">{hop.by_host}</span></span>}
                    {hop.ip && <span className="text-zinc-600"> [{hop.ip}]</span>}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

    </div>
  )
}
