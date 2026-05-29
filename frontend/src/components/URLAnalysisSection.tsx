import type { URLAnalysisResult, URLFeatures } from '../types/scan'

interface Props {
  analysis: URLAnalysisResult
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + '…' : s
}

function EntropyBar({ value }: { value: number }) {
  const pct = Math.min((value / 6) * 100, 100)
  const color = value > 4.5 ? 'bg-red-500' : value > 3.5 ? 'bg-amber-500' : 'bg-emerald-500'
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[10px] text-zinc-500 tabular-nums">{value.toFixed(2)}</span>
    </div>
  )
}

function URLRow({ feat, isHighRisk }: { feat: URLFeatures; isHighRisk: boolean }) {
  const tags: { label: string; cls: string }[] = []
  if (feat.is_shortener) tags.push({ label: 'Shortener', cls: 'text-amber-400 bg-amber-500/10 border-amber-500/20' })
  if (feat.has_credential_keywords) tags.push({ label: 'Credentials', cls: 'text-red-400 bg-red-500/10 border-red-500/20' })
  if (feat.has_homograph) tags.push({ label: 'Homograph', cls: 'text-red-400 bg-red-500/10 border-red-500/20' })
  if (feat.redirect_chain.length > 2) tags.push({ label: `${feat.redirect_chain.length - 1} Redirects`, cls: 'text-amber-400 bg-amber-500/10 border-amber-500/20' })

  return (
    <div className={`py-3 border-b border-zinc-800/60 last:border-0 ${isHighRisk ? 'border-l-2 border-l-red-500/40 pl-3 -ml-5 pr-5' : ''}`}>
      <div className="flex items-start gap-2 mb-1.5">
        {isHighRisk && <span className="mt-0.5 h-1.5 w-1.5 rounded-full bg-red-500 flex-shrink-0 shadow-[0_0_6px_#ef4444]" />}
        <p className="text-[11px] font-mono text-zinc-400 break-all leading-snug">
          {truncate(feat.url, 100)}
        </p>
      </div>

      <div className="flex items-center gap-3 flex-wrap mt-1">
        {feat.entropy !== null && <EntropyBar value={feat.entropy} />}
        {tags.map(t => (
          <span key={t.label} className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wider ${t.cls}`}>
            {t.label}
          </span>
        ))}
        {feat.ml_phishing_score !== null && (
          <span className={`text-[10px] tabular-nums ${feat.ml_phishing_score > 0.6 ? 'text-red-400' : 'text-zinc-500'}`}>
            ML: {(feat.ml_phishing_score * 100).toFixed(0)}%
          </span>
        )}
      </div>

      {feat.is_shortener && feat.redirect_chain.length > 1 && feat.final_url && (
        <p className="text-[10px] text-zinc-600 mt-1 pl-3">
          → <span className="font-mono">{truncate(feat.final_url, 80)}</span>
        </p>
      )}
    </div>
  )
}

export function URLAnalysisSection({ analysis }: Props) {
  const highRiskSet = new Set(analysis.high_risk_urls)

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
      <div className="px-5 py-3 border-b border-zinc-800 flex items-center justify-between">
        <span className="text-[10px] font-semibold text-zinc-500 uppercase tracking-widest">
          URL Analysis
        </span>
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-zinc-600">{analysis.extracted_urls.length} URL{analysis.extracted_urls.length !== 1 ? 's' : ''}</span>
          {analysis.high_risk_urls.length > 0 && (
            <span className="text-[10px] font-bold px-2 py-0.5 rounded border bg-red-500/15 text-red-400 border-red-500/30 uppercase tracking-wider">
              {analysis.high_risk_urls.length} High Risk
            </span>
          )}
        </div>
      </div>

      <div className="px-5">
        {analysis.analyzed_urls.length === 0 ? (
          <p className="py-4 text-sm text-zinc-600">No URLs analyzed</p>
        ) : (
          analysis.analyzed_urls.map((feat, i) => (
            <URLRow key={i} feat={feat} isHighRisk={highRiskSet.has(feat.url)} />
          ))
        )}
      </div>

      {analysis.extracted_urls.length > analysis.analyzed_urls.length && (
        <div className="px-5 pb-3">
          <p className="text-[10px] text-zinc-700">
            +{analysis.extracted_urls.length - analysis.analyzed_urls.length} more URLs not shown
          </p>
        </div>
      )}
    </div>
  )
}
