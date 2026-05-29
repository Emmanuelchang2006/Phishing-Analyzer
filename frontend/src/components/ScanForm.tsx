import { useState } from 'react'
import type { ScanOptions, ScanRequest, ScanResponse, ScanType } from '../types/scan'
import { submitScan } from '../api/client'

interface Props {
  onResult: (result: ScanResponse) => void
}

const SCAN_TYPES: { value: ScanType; label: string }[] = [
  { value: 'url', label: 'URL' },
  { value: 'domain', label: 'Domain' },
  { value: 'ip', label: 'IP Address' },
  { value: 'email', label: 'Email Headers' },
]

// Only surface the options the user needs to toggle; sprint 2 options always run
const OPTION_LABELS: Partial<Record<keyof ScanOptions, string>> = {
  check_virustotal: 'VirusTotal',
  check_abuseipdb: 'AbuseIPDB',
  check_whois: 'WHOIS',
  check_email_auth: 'Email Auth',
  generate_ai_verdict: 'AI Verdict (Gemini)',
}

const DEFAULT_OPTIONS: ScanOptions = {
  check_virustotal: true,
  check_abuseipdb: true,
  check_whois: true,
  check_email_auth: true,
  generate_ai_verdict: true,
  check_typosquatting: true,
  check_url_analysis: true,
  check_keywords: true,
  generate_mitre_mapping: true,
}

const PLACEHOLDERS: Record<ScanType, string> = {
  url: 'https://suspicious-login.example.com/verify?token=abc123',
  domain: 'suspicious-domain.com',
  ip: '192.0.2.1',
  email: 'Paste raw email headers here...\n\nFrom: sender@example.com\nReceived: from mail.example.com...',
}

export function ScanForm({ onResult }: Props) {
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState<ScanType>('url')
  const [options, setOptions] = useState<ScanOptions>(DEFAULT_OPTIONS)
  const [showOptions, setShowOptions] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    try {
      const request: ScanRequest = { target: target.trim(), scan_type: scanType, options }
      const result = await submitScan(request)
      onResult(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred')
    } finally {
      setLoading(false)
    }
  }

  const toggleOption = (key: keyof ScanOptions) => {
    setOptions(prev => ({ ...prev, [key]: !prev[key] }))
  }

  const optionKeys = Object.keys(OPTION_LABELS) as (keyof typeof OPTION_LABELS)[]

  return (
    <form onSubmit={handleSubmit} className="bg-zinc-900 border border-zinc-800 rounded-xl">
      <div className="p-5 space-y-4">

        {/* Scan type selector */}
        <div className="flex gap-1 bg-zinc-950 rounded-lg p-1">
          {SCAN_TYPES.map(type => (
            <button
              key={type.value}
              type="button"
              onClick={() => setScanType(type.value)}
              className={`flex-1 py-1.5 rounded-md text-xs font-semibold transition-all ${
                scanType === type.value
                  ? 'bg-cyan-500 text-zinc-950 shadow-sm'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              {type.label}
            </button>
          ))}
        </div>

        {/* Target input */}
        <textarea
          value={target}
          onChange={e => setTarget(e.target.value)}
          placeholder={PLACEHOLDERS[scanType]}
          rows={scanType === 'email' ? 5 : 2}
          className="w-full bg-zinc-950 border border-zinc-700 rounded-lg px-3 py-2.5 text-sm font-mono
                     text-zinc-200 placeholder-zinc-700
                     focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30
                     resize-y transition-colors"
          required
        />

        {/* Analysis modules toggle */}
        <div>
          <button
            type="button"
            onClick={() => setShowOptions(v => !v)}
            className="flex items-center gap-1.5 text-xs font-medium text-zinc-600 hover:text-zinc-400 transition-colors"
          >
            <svg
              className={`h-3 w-3 transition-transform ${showOptions ? 'rotate-90' : ''}`}
              viewBox="0 0 20 20" fill="currentColor"
            >
              <path fillRule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clipRule="evenodd" />
            </svg>
            Analysis modules
          </button>

          {showOptions && (
            <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3 pl-4">
              {optionKeys.map(key => (
                <label key={key} className="flex items-center gap-2 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={options[key]}
                    onChange={() => toggleOption(key)}
                    className="rounded border-zinc-700 bg-zinc-800 text-cyan-500
                               focus:ring-cyan-500 focus:ring-offset-0 focus:ring-offset-zinc-900"
                  />
                  <span className="text-xs text-zinc-600 group-hover:text-zinc-400 transition-colors">
                    {OPTION_LABELS[key]}
                  </span>
                </label>
              ))}
            </div>
          )}
        </div>

        {/* Error */}
        {error && (
          <div className="rounded-lg bg-red-500/10 border border-red-500/20 p-3 flex items-start gap-2.5">
            <svg className="h-4 w-4 text-red-500 mt-0.5 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
            </svg>
            <span className="text-sm text-red-400">{error}</span>
          </div>
        )}

        {/* Submit */}
        <button
          type="submit"
          disabled={loading || !target.trim()}
          className="w-full py-2.5 px-4
                     bg-cyan-500 hover:bg-cyan-400 active:bg-cyan-600
                     disabled:bg-zinc-800 disabled:text-zinc-600 disabled:cursor-not-allowed
                     text-zinc-950 font-bold rounded-lg transition-colors text-sm
                     flex items-center justify-center gap-2"
        >
          {loading ? (
            <>
              <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Scanning…
            </>
          ) : (
            <>
              <svg className="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd" />
              </svg>
              Analyze Target
            </>
          )}
        </button>

      </div>
    </form>
  )
}
