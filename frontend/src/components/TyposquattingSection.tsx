import type { TyposquattingResult } from '../types/scan'

interface Props {
  typo: TyposquattingResult
}

export function TyposquattingSection({ typo }: Props) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
      <div className="px-5 py-3 border-b border-zinc-800 flex items-center justify-between">
        <span className="text-[10px] font-semibold text-zinc-500 uppercase tracking-widest">
          Typosquatting Detection
        </span>
        {typo.is_typosquatting ? (
          <span className="text-[10px] font-bold px-2 py-0.5 rounded border bg-red-500/15 text-red-400 border-red-500/30 uppercase tracking-wider">
            DETECTED
          </span>
        ) : (
          <span className="text-[10px] font-bold px-2 py-0.5 rounded border bg-emerald-500/15 text-emerald-400 border-emerald-500/30 uppercase tracking-wider">
            CLEAN
          </span>
        )}
      </div>

      <div className="px-5 py-4">
        {typo.checked_domain && (
          <p className="text-xs text-zinc-500 mb-3">
            Checked: <span className="font-mono text-zinc-300">{typo.checked_domain}</span>
          </p>
        )}

        {typo.is_typosquatting && typo.matches.length > 0 ? (
          <div className="space-y-2">
            {typo.matches.map((m, i) => (
              <div key={i} className="flex items-center gap-3 py-2 border-b border-zinc-800/60 last:border-0">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-xs font-semibold text-red-400">{m.brand}</span>
                    <span className="text-[10px] text-zinc-600">→</span>
                    <span className="text-xs font-mono text-zinc-400">{m.brand_domain}</span>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className="text-[10px] text-zinc-600">
                    dist <span className="text-amber-400 font-bold">{m.distance}</span>
                  </span>
                  <div className="w-16 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-amber-500 rounded-full"
                      style={{ width: `${m.similarity * 100}%` }}
                    />
                  </div>
                  <span className="text-[10px] text-zinc-500 w-8 text-right">
                    {(m.similarity * 100).toFixed(0)}%
                  </span>
                </div>
              </div>
            ))}
            <p className="text-[10px] text-zinc-700 mt-1">
              Domain closely resembles known brand{typo.matches.length > 1 ? 's' : ''} — possible brand impersonation
            </p>
          </div>
        ) : (
          <p className="text-sm text-zinc-600">No brand impersonation detected</p>
        )}
      </div>
    </div>
  )
}
