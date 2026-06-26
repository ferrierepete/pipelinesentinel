'use client'

import { useState, useCallback } from 'react'
import ScanForm from '@/components/ScanForm'
import ScanResults from '@/components/ScanResults'
import type { ScanResult } from '@/components/ScanResults'

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://127.0.0.1:8742'

const STEP_LABELS: Record<string, string> = {
  parse_dependencies: 'Parsing dependencies...',
  ingest_osv: 'Querying OSV vulnerability database...',
  ingest_ghsa: 'Querying GitHub Security Advisories...',
  ingest_kev: 'Checking CISA Known Exploited Vulnerabilities...',
  correlate_findings: 'Cross-referencing findings...',
  assess_risk: 'Calculating risk scores...',
  generate_briefing: 'Generating remediation briefing...',
}

export default function Home() {
  const [result, setResult] = useState<ScanResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [logs, setLogs] = useState<string[]>([])
  const [completedSteps, setCompletedSteps] = useState<string[]>([])
  const [useStreaming, setUseStreaming] = useState(true)

  const handleScanSSE = useCallback(async (fileContent: string, fileName: string) => {
    setLoading(true)
    setResult(null)
    setLogs(['Starting scan...'])
    setCompletedSteps([])

    try {
      const response = await fetch(`${API_BASE}/api/scan/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file_content: fileContent, file_name: fileName }),
      })

      if (!response.ok) {
        throw new Error(`Scan failed: ${response.statusText}`)
      }

      const reader = response.body?.getReader()
      if (!reader) {
        throw new Error('No response stream available')
      }

      const decoder = new TextDecoder()
      let buffer = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })

        // Parse SSE events from buffer
        const lines = buffer.split('\n')
        buffer = ''

        let currentEvent = ''
        let currentData = ''

        for (const line of lines) {
          if (line.startsWith('event: ')) {
            currentEvent = line.slice(7).trim()
          } else if (line.startsWith('data: ')) {
            currentData = line.slice(6)
          } else if (line === '' && currentEvent && currentData) {
            // Dispatch complete event
            try {
              const data = JSON.parse(currentData)

              if (currentEvent === 'progress') {
                const stepMessage = STEP_LABELS[data.step] || data.message || data.step
                setLogs(prev => [...prev, stepMessage])
                if (data.completed) {
                  setCompletedSteps(data.completed)
                }
              } else if (currentEvent === 'complete') {
                setResult(data)
                setLogs(prev => [...prev, '✅ Scan complete'])
              } else if (currentEvent === 'error') {
                setLogs(prev => [...prev, `❌ Error: ${data.error}`])
              }
            } catch {
              // Ignore parse errors for partial data
            }

            currentEvent = ''
            currentData = ''
          } else if (line !== '') {
            // Incomplete line — keep in buffer
            buffer = line
          }
        }
      }
    } catch (err) {
      setLogs(prev => [...prev, `Error: ${err instanceof Error ? err.message : 'Unknown error'}`])
      // Fallback: try non-streaming endpoint
      try {
        const fallback = await fetch(`${API_BASE}/api/scan`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ file_content: fileContent, file_name: fileName }),
        })
        if (fallback.ok) {
          const data = await fallback.json()
          setResult(data)
          setLogs(prev => [...prev, '✅ Scan complete (fallback mode)'])
        }
      } catch {
        // Both failed
      }
    } finally {
      setLoading(false)
    }
  }, [])

  const handleScanFallback = useCallback(async (fileContent: string, fileName: string) => {
    setLoading(true)
    setResult(null)
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
      setLogs(prev => [...prev, '✅ Scan complete'])
    } catch (err) {
      setLogs([`Error: ${err instanceof Error ? err.message : 'Unknown error'}`])
    } finally {
      setLoading(false)
    }
  }, [])

  const handleScan = useCallback(async (fileContent: string, fileName: string) => {
    if (useStreaming) {
      await handleScanSSE(fileContent, fileName)
    } else {
      await handleScanFallback(fileContent, fileName)
    }
  }, [useStreaming, handleScanSSE, handleScanFallback])

  const totalSteps = Object.keys(STEP_LABELS).length
  const progress = Math.round((completedSteps.length / totalSteps) * 100)

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
        <div className="mt-6 bg-slate-900 border border-slate-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium text-slate-400">Scan Progress</h3>
            {loading && completedSteps.length > 0 && (
              <div className="flex items-center gap-2">
                <div className="w-32 h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-blue-500 transition-all duration-500"
                    style={{ width: `${progress}%` }}
                  />
                </div>
                <span className="text-xs text-slate-500">{progress}%</span>
              </div>
            )}
          </div>
          <div className="max-h-48 overflow-y-auto space-y-0.5">
            {logs.map((log, i) => (
              <div
                key={i}
                className={`font-mono text-sm ${
                  log.startsWith('❌') ? 'text-red-400' :
                  log.startsWith('✅') ? 'text-green-400' :
                  'text-slate-400'
                }`}
              >
                {log}
              </div>
            ))}
            {loading && (
              <div className="font-mono text-sm text-slate-500 flex items-center gap-2">
                <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Processing...
              </div>
            )}
          </div>
        </div>
      )}

      {/* Results */}
      {result && <ScanResults result={result} />}
    </main>
  )
}
