import { useRef, useState } from 'react'
import { ScanForm } from './components/ScanForm'
import { ScanHistory } from './components/ScanHistory'
import { ScanResult } from './components/ScanResult'
import type { ScanResponse } from './types/scan'

type Tab = 'analyze' | 'history'

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>('analyze')
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null)
  const resultRef = useRef<HTMLDivElement>(null)

  const handleResult = (result: ScanResponse) => {
    setScanResult(result)
    setActiveTab('analyze')
    setTimeout(() => {
      resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }, 100)
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <header className="sticky top-0 z-10 border-b border-zinc-800 bg-zinc-950/95 backdrop-blur">
        <div className="max-w-5xl mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between h-14">
            <div className="flex items-center gap-3">
              <div className="flex items-center justify-center w-7 h-7 rounded-md bg-cyan-500/10 border border-cyan-500/20">
                <svg className="h-4 w-4 text-cyan-400" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" />
                </svg>
              </div>
              <div>
                <span className="text-sm font-bold tracking-tight text-zinc-100">PhishDetect</span>
                <span className="ml-2 text-xs text-zinc-600 hidden sm:inline">threat intelligence</span>
              </div>
            </div>

            <nav className="flex">
              {(['analyze', 'history'] as Tab[]).map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-4 h-14 text-sm font-medium border-b-2 transition-colors capitalize ${
                    activeTab === tab
                      ? 'border-cyan-500 text-cyan-400'
                      : 'border-transparent text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  {tab}
                </button>
              ))}
            </nav>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 sm:px-6 py-6">
        {activeTab === 'analyze' ? (
          <div className="space-y-5">
            <ScanForm onResult={handleResult} />
            {scanResult && (
              <div ref={resultRef}>
                <ScanResult result={scanResult} />
              </div>
            )}
          </div>
        ) : (
          <ScanHistory onSelectScan={handleResult} />
        )}
      </main>
    </div>
  )
}
