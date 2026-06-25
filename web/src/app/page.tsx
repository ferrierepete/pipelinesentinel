'use client'

import { useState, useCallback } from 'react'
import ScanForm from '@/components/ScanForm'
import ScanResults from '@/components/ScanResults'
import type { ScanResult } from '@/components/ScanResults'

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://127.0.0.1:8742'

export default function Home() {
  const [result, setResult] = useState<ScanResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [logs, setLogs] = useState<string[]>([])

  const handleScan = useCallback(async (fileContent: string, fileName: string) => {
    setLoading(true)
    setResult(null)
    setLogs([])

    // Add scan log messages
    setLogs(['Parsing dependencies...', 'Querying OSV database...', 'Querying GitHub Advisories...', 'Checking CISA KEV...', 'Correlating findings...', 'Assessing risk scores...', 'Generating briefing...'])

    try {
      const response = await fetch(`${API_BASE}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file_content: fileContent, file_name: fileName }),
      })

      if (!response.ok) {
        throw new Error(`Scan failed: ${response.statusText}`)
      }

      const data = await response.json()
      setResult(data)
    } catch (err) {
      setLogs([`Error: ${err instanceof Error ? err.message : 'Unknown error'}`])
    } finally {
      setLoading(false)
    }
  }, [])

  return (
    <main className="max-w-6xl mx-auto px-4 py-8">
      {/* Hero */}
      <div className="text-center mb-12">
        <div className="flex items-center justify-center gap-3 mb-4">
          <span className="text-4xl">🛡️</span>
          <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
            PipelineSentinel
          </h1>
        </div>
        <p className="text-slate-400 text-lg max-w-2xl mx-auto">
          AI/ML Dependency Vulnerability Intelligence. Scan your AI pipeline dependencies for known vulnerabilities, 
          AI-specific attack vectors, and CISA KEV exploitation status.
        </p>
      </div>

      {/* Scan Input */}
      <ScanForm onScan={handleScan} loading={loading} />

      {/* Live Logs */}
      {logs.length > 0 && (
        <div className="mt-6 bg-slate-900 border border-slate-700 rounded-lg p-4 max-h-48 overflow-y-auto">
          {logs.map((log, i) => (
            <div key={i} className="font-mono text-sm text-slate-400">{log}</div>
          ))}
        </div>
      )}

      {/* Results */}
      {result && <ScanResults result={result} />}
    </main>
  )
}
