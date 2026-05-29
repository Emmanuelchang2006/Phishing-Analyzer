import type { WhoisResult } from '../types/scan'

interface Props {
  whois: WhoisResult
}

function formatDate(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
  })
}

export function WhoisSection({ whois }: Props) {
  const ageStr = whois.domain_age_days != null ? `${whois.domain_age_days} days` : '—'
  const hasData = whois.domain_age_days != null || whois.registrar != null || whois.creation_date != null

  const fields: { label: string; value: string; warn?: boolean }[] = [
    { label: 'Age', value: ageStr, warn: whois.recently_registered },
    { label: 'Country', value: whois.country ?? '—' },
    { label: 'Registered', value: formatDate(whois.creation_date) },
    { label: 'Expires', value: formatDate(whois.expiration_date) },
  ]

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
      <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
        <h3 className="text-[10px] font-semibold text-zinc-500 uppercase tracking-widest">WHOIS</h3>
        {whois.recently_registered && (
          <span className="text-[10px] font-bold text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded uppercase tracking-wider">
            New Domain
          </span>
        )}
      </div>

      {hasData ? (
        <>
          <div className="grid grid-cols-2 gap-px bg-zinc-800">
            {fields.map(({ label, value, warn }) => (
              <div key={label} className="bg-zinc-900 px-4 py-3">
                <p className="text-[10px] text-zinc-600 uppercase tracking-wider mb-1">{label}</p>
                <p className={`text-sm font-medium ${warn ? 'text-amber-400' : 'text-zinc-300'}`}>{value}</p>
              </div>
            ))}
          </div>
          <div className="px-4 py-3 border-t border-zinc-800">
            <p className="text-[10px] text-zinc-600 uppercase tracking-wider mb-1">Registrar</p>
            <p className="text-sm font-medium text-zinc-300 truncate">{whois.registrar ?? '—'}</p>
          </div>
        </>
      ) : (
        <div className="px-4 py-8 text-center">
          <p className="text-sm text-zinc-600">No WHOIS data available</p>
        </div>
      )}
    </div>
  )
}
