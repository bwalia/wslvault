'use client'
import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/contexts/AuthContext'
import Sidebar from '@/components/Sidebar'
import AppBar from '@/components/AppBar'
import BuildStamp from '@/components/BuildStamp'
import { PageTransition } from '@/components/PageTransition'

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
        className={`flex flex-col flex-1 min-w-0 transition-all duration-200 ${sidebarOpen ? 'ml-64' : 'ml-[4.5rem]'}`}
      >
        <AppBar onMenuClick={() => setSidebarOpen(o => !o)} />
        {/* The content plane. The faint radial wash lifts it off a flat fill —
            a vault interior is lit from somewhere, and a completely even
            background is the thing that makes an app look like a wireframe. */}
        <main className="flex-1 overflow-auto relative">
          <div
            aria-hidden="true"
            className="pointer-events-none fixed inset-0 bg-[radial-gradient(ellipse_at_top,var(--surface)_0%,transparent_55%)] opacity-60"
          />
          <div className="relative max-w-7xl mx-auto px-6 py-8 w-full">
            <PageTransition>{children}</PageTransition>
          </div>
        </main>
        <footer className="border-t border-line px-6 py-2.5">
          <BuildStamp className="text-xs text-ink-faint" />
        </footer>
      </div>
    </div>
  )
}
