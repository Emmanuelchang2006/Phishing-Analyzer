import type { MITREResult } from '../types/scan'

interface Props {
  mitre: MITREResult
}

const TACTIC_COLORS: Record<string, string> = {
  'Initial Access':    'text-red-400 bg-red-500/10 border-red-500/20',
  'Execution':         'text-orange-400 bg-orange-500/10 border-orange-500/20',
  'Defense Evasion':   'text-amber-400 bg-amber-500/10 border-amber-500/20',
  'Credential Access': 'text-purple-400 bg-purple-500/10 border-purple-500/20',
  'Reconnaissance':    'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
}

function tacticColor(tactic: string): string {
  return TACTIC_COLORS[tactic] ?? 'text-zinc-400 bg-zinc-800 border-zinc-700'
}

export function MITRESection({ mitre }: Props) {
  if (mitre.techniques.length === 0) return null

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
      <div className="px-5 py-3 border-b border-zinc-800 flex items-center justify-between">
        <span className="text-[10px] font-semibold text-zinc-500 uppercase tracking-widest">
          MITRE ATT&CK Mapping
        </span>
        <span className="text-[10px] text-zinc-600">
          {mitre.techniques.length} technique{mitre.techniques.length !== 1 ? 's' : ''}
        </span>
      </div>

      <div className="divide-y divide-zinc-800/60">
        {mitre.techniques.map((t, i) => (
          <div key={i} className="px-5 py-3">
            <div className="flex items-start gap-3">
              <div className="flex-shrink-0 mt-0.5">
                <span className="text-[11px] font-bold font-mono text-zinc-300 bg-zinc-800 px-1.5 py-0.5 rounded">
                  {t.technique_id}
                </span>
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <span className="text-sm font-semibold text-zinc-200">{t.technique_name}</span>
                  <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wider ${tacticColor(t.tactic)}`}>
                    {t.tactic}
                  </span>
                </div>
                <p className="text-[11px] text-zinc-500 leading-snug">{t.reason}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="px-5 py-2 border-t border-zinc-800/60">
        <p className="text-[10px] text-zinc-700">
          Rule-based MITRE ATT&CK mapping based on detected indicators
        </p>
      </div>
    </div>
  )
}
