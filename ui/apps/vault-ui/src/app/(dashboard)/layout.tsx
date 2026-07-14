'use client'
import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/contexts/AuthContext'
import Sidebar from '@/components/Sidebar'
import AppBar from '@/components/AppBar'

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth()
  const router = useRouter()
  const [sidebarOpen, setSidebarOpen] = useState(true)

  useEffect(() => {
    if (!isAuthenticated) router.replace('/login')
  }, [isAuthenticated, router])

  if (!isAuthenticated) return null

  return (
    <div className="flex h-screen bg-canvas">
      <Sidebar open={sidebarOpen} onToggle={() => setSidebarOpen(o => !o)} />
      <div
        className={`flex flex-col flex-1 min-w-0 transition-all duration-200 ${sidebarOpen ? 'ml-60' : 'ml-16'}`}
      >
        <AppBar onMenuClick={() => setSidebarOpen(o => !o)} />
        <main className="flex-1 overflow-auto">
          <div className="max-w-7xl mx-auto px-6 py-6 w-full">{children}</div>
        </main>
        <footer className="border-t border-line px-6 py-2.5">
          <p className="text-xs text-ink-faint font-mono">wslvault v0.1.0 · local build</p>
        </footer>
      </div>
    </div>
  )
}
