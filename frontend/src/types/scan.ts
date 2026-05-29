export type ScanType = 'url' | 'domain' | 'ip' | 'email'
export type RiskLevel = 'clean' | 'suspicious' | 'malicious' | 'unknown'
export type VerdictType = 'phishing' | 'suspicious' | 'legitimate' | 'unknown'

export interface ScanOptions {
  check_virustotal: boolean
  check_abuseipdb: boolean
  check_whois: boolean
  check_email_auth: boolean
  generate_ai_verdict: boolean
  check_typosquatting: boolean
  check_url_analysis: boolean
  check_keywords: boolean
  generate_mitre_mapping: boolean
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

// ── Sprint 2 types ─────────────────────────────────────────────────────────

export interface TyposquattingMatch {
  brand: string
  brand_domain: string
  distance: number
  similarity: number
}

export interface TyposquattingResult {
  is_typosquatting: boolean
  matches: TyposquattingMatch[]
  checked_domain: string | null
}

export interface URLFeatures {
  url: string
  entropy: number | null
  is_shortener: boolean
  has_credential_keywords: boolean
  has_homograph: boolean
  redirect_chain: string[]
  final_url: string | null
  ml_phishing_score: number | null
}

export interface URLAnalysisResult {
  extracted_urls: string[]
  analyzed_urls: URLFeatures[]
  high_risk_urls: string[]
}

export interface KeywordMatch {
  keyword: string
  category: string
  weight: number
  context: string | null
}

export interface KeywordDetectionResult {
  matches: KeywordMatch[]
  total_weight: number
  categories: string[]
}

export interface MITRETactic {
  technique_id: string
  technique_name: string
  tactic: string
  reason: string
}

export interface MITREResult {
  techniques: MITRETactic[]
}

export interface ReceivedHop {
  raw: string
  from_host: string | null
  by_host: string | null
  ip: string | null
  timestamp: string | null
}

export interface EmailHeadersAnalysis {
  hop_count: number
  hops: ReceivedHop[]
  originating_ip: string | null
  x_mailer: string | null
  suspicious_mailer: boolean
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
  typosquatting: TyposquattingResult | null
  url_analysis: URLAnalysisResult | null
  keywords: KeywordDetectionResult | null
  mitre_tactics: MITREResult | null
  email_headers: EmailHeadersAnalysis | null
  scanned_at: string
  duration_ms: number | null
}
