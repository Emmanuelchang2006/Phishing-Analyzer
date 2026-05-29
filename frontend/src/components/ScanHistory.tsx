import { useEffect, useState } from 'react'
import { getRecentScans } from '../api/client'
import type { RiskLevel, ScanResponse } from '../types/scan'

interface Props {
  onSelectScan: (result: ScanResponse) => void
}

type Filter = RiskLevel | 'all'

const FILTERS: { label: string; value: Filter }[] = [
  { label: 'All', value: 'all' },
  { label: 'Clean', value: 'clean' },
  { label: 'Suspicious', value: 'suspicious' },
  { label: 'Malicious', value: 'malicious' },
]

const LEVEL_BADGE: Record<RiskLevel, string> = {
  malicious: 'bg-red-500/15 text-red-400 border-red-500/30',
  suspicious: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  clean: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  unknown: 'bg-zinc-700 text-zinc-400 border-zinc-600',
}

const SCORE_COLOR: Record<RiskLevel, string> = {
  malicious: 'text-red-400',
  suspicious: 'text-amber-400',
  clean: 'text-emerald-400',
  unknown: 'text-zinc-500',
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + '…' : s
}

export function ScanHistory({ onSelectScan }: Props) {
  const [scans, setScans] = useState<ScanResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState<Filter>('all')

  useEffect(() => {
    setLoading(true)
    setError(null)
    const riskLevel = filter === 'all' ? undefined : filter
    getRecentScans(50, riskLevel)
      .then(setScans)
      .catch(err => {
        setError(err instanceof Error ? err.message : 'Failed to load scan history')
      })
      .finally(() => setLoading(false))
  }, [filter])

  return (
    <div className="space-y-4">

      {/* Header + filters */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <h2 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest">Scan History</h2>
        <div className="flex gap-1 bg-zinc-900 border border-zinc-800 rounded-lg p-1">
          {FILTERS.map(f => (
            <button
              key={f.value}
              onClick={() => setFilter(f.value)}
              className={`px-3 py-1 rounded-md text-xs font-semibold transition-colors ${
                filter === f.value
                  ? 'bg-cyan-500 text-zinc-950'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
        {loading ? (
          <div className="py-16 flex flex-col items-center gap-3 text-zinc-600">
            <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            <span className="text-sm">Loading…</span>
          </div>
        ) : error ? (
          <div className="py-12 text-center">
            <p className="text-sm text-zinc-400">Failed to load history</p>
            <p className="text-xs text-zinc-600 mt-1">{error}</p>
          </div>
        ) : scans.length === 0 ? (
          <div className="py-16 text-center">
            <svg className="h-7 w-7 mx-auto mb-3 text-zinc-700" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" />
            </svg>
            <p className="text-sm text-zinc-600">No scans found</p>
            {filter !== 'all' && (
              <p className="text-xs text-zinc-700 mt-1">Try a different filter</p>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800">
                  <th className="text-left px-4 py-2.5 text-[10px] font-semibold text-zinc-600 uppercase tracking-widest">
                    Target
                  </th>
                  <th className="text-left px-4 py-2.5 text-[10px] font-semibold text-zinc-600 uppercase tracking-widest w-20">
                    Type
                  </th>
                  <th className="text-center px-4 py-2.5 text-[10px] font-semibold text-zinc-600 uppercase tracking-widest w-40">
                    Risk
                  </th>
                  <th className="text-right px-4 py-2.5 text-[10px] font-semibold text-zinc-600 uppercase tracking-widest w-36 hidden sm:table-cell">
                    Scanned
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {scans.map(scan => {
                  const level = scan.risk_score?.level ?? 'unknown'
                  return (
                    <tr
                      key={scan.scan_id}
                      onClick={() => onSelectScan(scan)}
                      className="cursor-pointer hover:bg-zinc-800/50 transition-colors group"
                    >
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs text-zinc-500 group-hover:text-zinc-300 transition-colors">
                          {truncate(scan.target, 90)}
                        </span>
                        {scan.ai_verdict && (
                          <span className="ml-2 text-[10px] font-semibold text-cyan-700">AI</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-[10px] font-semibold bg-zinc-800 text-zinc-500 px-1.5 py-0.5 rounded uppercase tracking-wider">
                          {scan.scan_type}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        {scan.risk_score ? (
                          <div className="flex items-center justify-center gap-2">
                            <span className={`font-black tabular-nums ${SCORE_COLOR[level]}`}>
                              {scan.risk_score.score}
                            </span>
                            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wider ${LEVEL_BADGE[level]}`}>
                              {level}
                            </span>
                          </div>
                        ) : (
                          <span className="text-zinc-700 text-center block">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right text-xs text-zinc-600 hidden sm:table-cell">
                        {new Date(scan.scanned_at).toLocaleString(undefined, {
                          dateStyle: 'short',
                          timeStyle: 'short',
                        })}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <p className="text-xs text-zinc-700 text-center">
        Click any row to view full scan details
      </p>
    </div>
  )
}
