import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'PipelineSentinel — AI/ML Dependency Vulnerability Intelligence',
  description: 'LangGraph AI agent that monitors your AI/ML pipeline dependencies for vulnerabilities, correlates AI-specific attack vectors, and generates remediation briefings.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-slate-950 text-slate-100 antialiased">
        {children}
      </body>
    </html>
  )
}
