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
    <div className="flex h-screen bg-slate-50 dark:bg-slate-950">
      <Sidebar open={sidebarOpen} onToggle={() => setSidebarOpen(o => !o)} />
      <div
        className={`flex flex-col flex-1 min-w-0 transition-all duration-300 ${sidebarOpen ? 'ml-64' : 'ml-18'}`}
      >
        <AppBar onMenuClick={() => setSidebarOpen(o => !o)} />
        <main className="flex-1 overflow-auto p-6">{children}</main>
        <footer className="border-t border-slate-200 dark:border-slate-800 px-6 py-3">
          <p className="text-xs text-slate-400 dark:text-slate-500">WSLVault v0.1.0 | Build local</p>
        </footer>
      </div>
    </div>
  )
}
