import type { KeywordDetectionResult } from '../types/scan'

interface Props {
  keywords: KeywordDetectionResult
}

const CATEGORY_COLORS: Record<string, string> = {
  urgency: 'text-red-400 bg-red-500/10 border-red-500/20',
  credential_theft: 'text-red-400 bg-red-500/10 border-red-500/20',
  financial: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  authority: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  delivery: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
}

function weightColor(w: number): string {
  if (w >= 4) return 'text-red-400'
  if (w >= 3) return 'text-amber-400'
  return 'text-zinc-400'
}

function riskLabel(total: number): { label: string; cls: string } {
  if (total >= 10) return { label: 'HIGH', cls: 'bg-red-500/15 text-red-400 border-red-500/30' }
  if (total >= 5) return { label: 'MODERATE', cls: 'bg-amber-500/15 text-amber-400 border-amber-500/30' }
  return { label: 'LOW', cls: 'bg-zinc-700 text-zinc-400 border-zinc-600' }
}

export function KeywordSection({ keywords }: Props) {
  const { label, cls } = riskLabel(keywords.total_weight)

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
      <div className="px-5 py-3 border-b border-zinc-800 flex items-center justify-between">
        <span className="text-[10px] font-semibold text-zinc-500 uppercase tracking-widest">
          Phishing Keywords
        </span>
        <div className="flex items-center gap-2">
          <span className="text-xs text-zinc-600">
            weight <span className={`font-bold ${weightColor(keywords.total_weight)}`}>{keywords.total_weight}</span>
          </span>
          <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wider ${cls}`}>
            {label}
          </span>
        </div>
      </div>

      <div className="px-5 py-4">
        {keywords.categories.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mb-3">
            {keywords.categories.map(cat => (
              <span
                key={cat}
                className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wider ${CATEGORY_COLORS[cat] ?? 'text-zinc-500 bg-zinc-800 border-zinc-700'}`}
              >
                {cat.replace('_', ' ')}
              </span>
            ))}
          </div>
        )}

        {keywords.matches.length === 0 ? (
          <p className="text-sm text-zinc-600">No phishing keywords detected</p>
        ) : (
          <div className="space-y-1.5">
            {keywords.matches.slice(0, 12).map((m, i) => (
              <div key={i} className="flex items-start gap-2.5">
                <span className={`mt-0.5 text-[9px] font-bold tabular-nums w-4 text-right flex-shrink-0 ${weightColor(m.weight)}`}>
                  {m.weight}
                </span>
                <div className="min-w-0">
                  <span className="text-xs text-zinc-300 font-mono">"{m.keyword}"</span>
                  {m.context && (
                    <p className="text-[10px] text-zinc-600 truncate mt-0.5">…{m.context}…</p>
                  )}
                </div>
              </div>
            ))}
            {keywords.matches.length > 12 && (
              <p className="text-[10px] text-zinc-700 mt-1">+{keywords.matches.length - 12} more matches</p>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
