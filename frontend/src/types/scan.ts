export type ScanType = 'url' | 'domain' | 'ip' | 'email'
export type RiskLevel = 'clean' | 'suspicious' | 'malicious' | 'unknown'
export type VerdictType = 'phishing' | 'suspicious' | 'legitimate' | 'unknown'

export interface ScanOptions {
  check_virustotal: boolean
  check_abuseipdb: boolean
  check_whois: boolean
  check_email_auth: boolean
  generate_ai_verdict: boolean
}

export interface ScanRequest {
  target: string
  scan_type: ScanType
  options?: Partial<ScanOptions>
}

export interface ThreatIntelResult {
  source: string
  detected: boolean | null
  score: number | null
  raw_data: Record<string, unknown> | null
  error: string | null
}

export interface EmailAuthResult {
  spf_status: string | null
  dkim_status: string | null
  dmarc_status: string | null
  from_domain: string | null
  reply_to_domain: string | null
  domain_mismatch: boolean
}

export interface WhoisResult {
  registrar: string | null
  creation_date: string | null
  expiration_date: string | null
  domain_age_days: number | null
  country: string | null
  recently_registered: boolean
}

export interface RiskScore {
  score: number
  level: RiskLevel
  confidence: number
  contributing_factors: string[]
}

export interface AIVerdict {
  verdict: VerdictType
  confidence: number
  executive_summary: string
  key_indicators: string[]
  recommended_action: string
  model: string
  cached: boolean
}

export interface ScanResponse {
  scan_id: string
  target: string
  scan_type: ScanType
  status: string
  risk_score: RiskScore | null
  threat_intel: ThreatIntelResult[]
  email_auth: EmailAuthResult | null
  whois: WhoisResult | null
  ai_verdict: AIVerdict | null
  scanned_at: string
  duration_ms: number | null
}
