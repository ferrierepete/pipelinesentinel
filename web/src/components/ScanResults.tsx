export interface Finding {
  source: string
  vuln_id: string
  package: string
  current_version: string
  summary: string
  details: string
  cvss: number
  risk_score: number
  priority: string
  ai_risk_category: string
  ai_risk_description: string
  ai_risk_modifier: number
  in_kev: boolean
  fix_version: string
  severity: string
}

export interface ScanResult {
  dependencies: Array<{ name: string; version: string }>
  ai_ml_deps: Array<{ name: string; version: string }>
  findings: Finding[]
  kev_entries: Array<{ cve_id: string; vulnerability_name: string }>
  briefing: string
  error?: string
}

interface ScanResultsProps {
  result: ScanResult
}

function severityColor(severity: string): string {
  switch (severity) {
    case 'CRITICAL': return 'severity-critical'
    case 'HIGH': return 'severity-high'
    case 'MEDIUM': return 'severity-medium'
    case 'LOW': return 'severity-low'
    default: return 'severity-info'
  }
}

export default function ScanResults({ result }: ScanResultsProps) {
  const { dependencies, ai_ml_deps, findings, kev_entries, briefing, error } = result

  if (error) {
    return (
      <div className="mt-6 bg-red-900/20 border border-red-500/30 rounded-xl p-6">
        <h3 className="text-red-400 font-bold text-lg mb-2">⚠️ Scan Error</h3>
        <p className="text-red-300">{error}</p>
      </div>
    )
  }

  return (
    <div className="mt-8 space-y-6">
      {/* KEV Banner */}
      {kev_entries && kev_entries.length > 0 && (
        <div className="bg-red-900/30 border-2 border-red-500/50 rounded-xl p-4 animate-pulse">
          <div className="flex items-center gap-2">
            <span className="text-2xl">⚡</span>
            <div>
              <h3 className="text-red-400 font-bold text-lg">
                {kev_entries.length} Known Exploited Vulnerability{kev_entries.length > 1 ? 'ies' : ''} Detected
              </h3>
              <p className="text-red-300 text-sm">
                {kev_entries.map(k => k.vulnerability_name).join(', ')}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
          <div className="text-slate-500 text-sm">Total Dependencies</div>
          <div className="text-2xl font-bold">{dependencies?.length || 0}</div>
        </div>
        <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
          <div className="text-slate-500 text-sm">AI/ML Dependencies</div>
          <div className="text-2xl font-bold text-blue-400">{ai_ml_deps?.length || 0}</div>
        </div>
        <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
          <div className="text-slate-500 text-sm">Vulnerabilities Found</div>
          <div className="text-2xl font-bold text-orange-400">{findings?.length || 0}</div>
        </div>
        <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
          <div className="text-slate-500 text-sm">Critical/High</div>
          <div className="text-2xl font-bold text-red-400">
            {findings?.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length || 0}
          </div>
        </div>
      </div>

      {/* Findings Table */}
      {findings && findings.length > 0 && (
        <div className="bg-slate-900 border border-slate-700 rounded-xl overflow-hidden">
          <h2 className="text-lg font-bold px-6 py-4 border-b border-slate-700">
            Vulnerability Findings
          </h2>
          <div className="divide-y divide-slate-800">
            {findings.map((finding, i) => (
              <div key={i} className="px-6 py-4 hover:bg-slate-800/50 transition-colors">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold border ${severityColor(finding.severity)}`}>
                        {finding.severity}
                      </span>
                      <span className="font-mono text-sm text-slate-300">{finding.package}</span>
                      <span className="text-slate-600">@</span>
                      <span className="font-mono text-sm text-slate-500">{finding.current_version || '?'}</span>
                      {finding.in_kev && (
                        <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                          ⚡ IN KEV
                        </span>
                      )}
                    </div>
                    <p className="text-slate-300 mt-1 text-sm">{finding.summary}</p>
                    <div className="flex items-center gap-4 mt-2 text-xs text-slate-500">
                      <span>CVSS: <span className="text-slate-300">{finding.cvss}</span></span>
                      <span>Risk: <span className="text-slate-300">{finding.risk_score}</span></span>
                      <span>AI Risk: <span className="text-slate-300">{finding.ai_risk_description}</span></span>
                      <span>Priority: <span className="font-bold text-slate-300">{finding.priority}</span></span>
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    {finding.fix_version ? (
                      <div className="text-green-400 text-sm font-mono">→ {finding.fix_version}</div>
                    ) : (
                      <div className="text-slate-600 text-sm">No fix</div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* No Findings */}
      {findings && findings.length === 0 && (
        <div className="bg-green-900/20 border border-green-500/30 rounded-xl p-6 text-center">
          <div className="text-4xl mb-2">✅</div>
          <h3 className="text-green-400 font-bold text-lg">No Vulnerabilities Found</h3>
          <p className="text-green-300 text-sm">Your AI/ML dependencies look clean.</p>
        </div>
      )}

      {/* Briefing */}
      {briefing && (
        <div className="bg-slate-900 border border-slate-700 rounded-xl overflow-hidden">
          <h2 className="text-lg font-bold px-6 py-4 border-b border-slate-700 flex items-center gap-2">
            📋 Remediation Briefing
          </h2>
          <div className="px-6 py-4 prose prose-invert max-w-none text-sm">
            <pre className="whitespace-pre-wrap font-sans text-slate-300">{briefing}</pre>
          </div>
        </div>
      )}
    </div>
  )
}
