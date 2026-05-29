import type { EmailAuthResult } from '../types/scan'

interface Props {
  auth: EmailAuthResult
}

function getStatus(status: string | null): {
  dot: string
  glow: string
  label: string
  textColor: string
} {
  if (status === 'pass') return {
    dot: 'bg-emerald-500',
    glow: 'shadow-[0_0_7px_#10b981]',
    label: 'pass',
    textColor: 'text-emerald-400',
  }
  if (status === 'softfail' || status === 'neutral') return {
    dot: 'bg-amber-500',
    glow: '',
    label: status,
    textColor: 'text-amber-400',
  }
  if (status === 'fail' || status === 'permerror' || status === 'temperror') return {
    dot: 'bg-red-500',
    glow: 'shadow-[0_0_7px_#ef4444]',
    label: status,
    textColor: 'text-red-400',
  }
  return {
    dot: 'bg-zinc-700',
    glow: '',
    label: 'none',
    textColor: 'text-zinc-600',
  }
}

function AuthRow({ label, status }: { label: string; status: string | null }) {
  const s = getStatus(status)
  return (
    <div className="px-4 py-3 flex items-center justify-between">
      <span className="text-sm font-semibold text-zinc-400">{label}</span>
      <div className="flex items-center gap-2.5">
        <span className={`h-2 w-2 rounded-full flex-shrink-0 ${s.dot} ${s.glow}`} />
        <span className={`text-xs font-semibold uppercase tracking-wider ${s.textColor}`}>
          {s.label}
        </span>
      </div>
    </div>
  )
}

export function EmailAuthSection({ auth }: Props) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
      <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
        <h3 className="text-[10px] font-semibold text-zinc-500 uppercase tracking-widest">Email Auth</h3>
        {auth.domain_mismatch && (
          <span className="text-[10px] font-bold text-red-400 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded uppercase tracking-wider">
            Domain Mismatch
          </span>
        )}
      </div>

      <div className="divide-y divide-zinc-800/50">
        <AuthRow label="SPF" status={auth.spf_status} />
        <AuthRow label="DKIM" status={auth.dkim_status} />
        <AuthRow label="DMARC" status={auth.dmarc_status} />
      </div>

      {(auth.from_domain || auth.reply_to_domain) && (
        <div className="border-t border-zinc-800 px-4 py-3 space-y-2.5">
          {auth.from_domain && (
            <div>
              <p className="text-[10px] text-zinc-600 uppercase tracking-wider mb-0.5">From</p>
              <p className="text-xs font-mono text-zinc-400">{auth.from_domain}</p>
            </div>
          )}
          {auth.reply_to_domain && auth.reply_to_domain !== auth.from_domain && (
            <div>
              <p className="text-[10px] text-zinc-600 uppercase tracking-wider mb-0.5">Reply-To</p>
              <p className="text-xs font-mono text-red-400">{auth.reply_to_domain}</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
