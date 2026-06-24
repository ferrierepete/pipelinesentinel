'use client'

import { useState, useRef } from 'react'

interface ScanFormProps {
  onScan: (fileContent: string, fileName: string) => void
  loading: boolean
}

const EXAMPLE_REQUIREMENTS = `# Example AI/ML dependencies
langchain>=0.1.0
langgraph>=0.2.0
openai>=1.0.0
litellm>=1.40.0
numpy>=1.24.0
transformers>=4.30.0
chromadb>=0.4.0
tiktoken>=0.5.0`

export default function ScanForm({ onScan, loading }: ScanFormProps) {
  const [input, setInput] = useState('')
  const [fileName, setFileName] = useState('requirements.txt')
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleSubmit = () => {
    const content = input.trim() || EXAMPLE_REQUIREMENTS
    onScan(content, fileName)
  }

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      setFileName(file.name)
      const reader = new FileReader()
      reader.onload = (e) => {
        setInput(e.target?.result as string)
      }
      reader.readAsText(file)
    }
  }

  return (
    <div className="bg-slate-900 border border-slate-700 rounded-xl p-6">
      {/* File Input */}
      <div className="flex items-center gap-4 mb-4">
        <div className="flex-1">
          <label className="block text-sm font-medium text-slate-400 mb-1">File Name</label>
          <input
            type="text"
            value={fileName}
            onChange={(e) => setFileName(e.target.value)}
            className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            placeholder="requirements.txt"
          />
        </div>
        <div className="flex flex-col items-center">
          <input
            ref={fileInputRef}
            type="file"
            accept=".txt,.toml,.json"
            onChange={handleFileUpload}
            className="hidden"
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded-lg text-sm transition-colors"
          >
            📁 Upload
          </button>
        </div>
      </div>

      {/* Content Input */}
      <div className="mb-4">
        <label className="block text-sm font-medium text-slate-400 mb-1">File Content</label>
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          rows={12}
          className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-y"
          placeholder={EXAMPLE_REQUIREMENTS}
        />
      </div>

      {/* Actions */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => setInput(EXAMPLE_REQUIREMENTS)}
          className="text-sm text-slate-500 hover:text-slate-300 transition-colors"
        >
          Load example
        </button>
        <button
          onClick={handleSubmit}
          disabled={loading}
          className="px-6 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed rounded-lg font-medium transition-colors"
        >
          {loading ? (
            <span className="flex items-center gap-2">
              <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Scanning...
            </span>
          ) : (
            '🔍 Scan Dependencies'
          )}
        </button>
      </div>
    </div>
  )
}
