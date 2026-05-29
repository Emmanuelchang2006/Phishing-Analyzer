import type { ScanRequest, ScanResponse } from '../types/scan'

const BASE = '/api/v1'

async function extractError(res: Response): Promise<string> {
  const text = await res.text().catch(() => '')
  if (!text) return `HTTP ${res.status}`
  try {
    const json = JSON.parse(text) as { detail?: unknown }
    const detail = json.detail
    if (typeof detail === 'string') return detail
    if (Array.isArray(detail) && detail.length > 0) {
      // FastAPI validation errors: [{loc, msg, type}, ...]
      const first = detail[0] as { msg?: string; loc?: unknown[] }
      const field = Array.isArray(first.loc) ? first.loc.join('.') : ''
      return field ? `Validation error on ${field}: ${first.msg}` : (first.msg ?? `HTTP ${res.status}`)
    }
    return `HTTP ${res.status}`
  } catch {
    // HTML error page — backend likely unreachable or crashed at startup
    if (text.includes('<html') || text.includes('ECONNREFUSED')) {
      return 'Backend is not reachable. Make sure the server is running on port 8000.'
    }
    return `HTTP ${res.status}: ${text.slice(0, 120)}`
  }
}

export async function submitScan(request: ScanRequest): Promise<ScanResponse> {
  let res: Response
  try {
    res = await fetch(`${BASE}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    })
  } catch {
    throw new Error('Backend is not reachable. Make sure the server is running on port 8000.')
  }
  if (!res.ok) {
    throw new Error(await extractError(res))
  }
  return res.json() as Promise<ScanResponse>
}

export async function getRecentScans(
  limit = 50,
  riskLevel?: string,
): Promise<ScanResponse[]> {
  let res: Response
  try {
    const params = new URLSearchParams({ limit: String(limit) })
    if (riskLevel) params.set('risk_level', riskLevel)
    res = await fetch(`${BASE}/scans?${params.toString()}`)
  } catch {
    return []
  }
  if (!res.ok) {
    if (res.status === 503) return []
    return []
  }
  return res.json() as Promise<ScanResponse[]>
}

export async function getScanById(scanId: string): Promise<ScanResponse> {
  let res: Response
  try {
    res = await fetch(`${BASE}/scan/${scanId}`)
  } catch {
    throw new Error('Backend is not reachable.')
  }
  if (!res.ok) throw new Error(await extractError(res))
  return res.json() as Promise<ScanResponse>
}
