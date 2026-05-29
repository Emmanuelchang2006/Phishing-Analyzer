import type { AIVerdict, VerdictType } from '../types/scan'

const VERDICT: Record<VerdictType, { accent: string; badge: string; label: string }> = {
  phishing: {
    accent: 'border-l-red-500/50',
    badge: 'bg-red-500/15 text-red-400 border-red-500/30',
    label: 'PHISHING',
  },
  suspicious: {
    accent: 'border-l-amber-500/50',
    badge: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    label: 'SUSPICIOUS',
  },
  legitimate: {
    accent: 'border-l-emerald-500/50',
    badge: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    label: 'LEGITIMATE',
  },
  unknown: {
    accent: 'border-l-zinc-600',
    badge: 'bg-zinc-700 text-zinc-400 border-zinc-600',
    label: 'UNKNOWN',
  },
}

interface Props {
  verdict: AIVerdict
}

export function AIVerdictCard({ verdict }: Props) {
  const cfg = VERDICT[verdict.verdict]

  return (
    <div className={`bg-zinc-900 border border-zinc-800 border-l-4 ${cfg.accent} rounded-xl overflow-hidden`}>

      {/* Header */}
      <div className="px-5 pt-4 pb-3 border-b border-zinc-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-semibold text-zinc-500 uppercase tracking-widest">
            AI Analysis
          </span>
          <span className="text-[10px] text-zinc-700">· {verdict.model}</span>
        </div>
        <div className="flex items-center gap-2.5">
          <span className="text-xs text-zinc-600 tabular-nums">
            {(verdict.confidence * 100).toFixed(0)}% confidence
          </span>
          <span className={`text-[10px] font-bold px-2 py-0.5 rounded border tracking-widest ${cfg.badge}`}>
            {cfg.label}
          </span>
        </div>
      </div>

      <div className="p-5 space-y-4">

        {/* Executive summary */}
        <p className="text-sm text-zinc-300 leading-relaxed">{verdict.executive_summary}</p>

        {/* Key indicators */}
        {verdict.key_indicators.length > 0 && (
          <div>
            <p className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest mb-2.5">
              Key Indicators
            </p>
            <ul className="space-y-1.5">
              {verdict.key_indicators.map((item, i) => (
                <li key={i} className="flex items-start gap-2.5 text-sm text-zinc-400">
                  <svg className="h-3.5 w-3.5 mt-0.5 flex-shrink-0 text-zinc-600" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clipRule="evenodd" />
                  </svg>
                  {item}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Recommended action */}
        <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-3.5">
          <p className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest mb-1.5">
            Recommended Action
          </p>
          <p className="text-sm text-zinc-300">{verdict.recommended_action}</p>
        </div>

      </div>
    </div>
  )
}
