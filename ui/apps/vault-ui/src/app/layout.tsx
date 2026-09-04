import type { Metadata } from 'next'
import { Lexend, Source_Sans_3, IBM_Plex_Mono } from 'next/font/google'
import './globals.css'
import { ThemeProvider } from '@/contexts/ThemeContext'
import { AuthProvider } from '@/contexts/AuthContext'
import { Providers } from './providers'

// Lexend for headings and UI chrome. Chosen deliberately over a stock grotesk:
// it was designed to reduce visual stress and improve reading proficiency, and
// this console has to be usable by someone who has never met a secrets manager.
const lexend = Lexend({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
  variable: '--font-display',
  display: 'swap',
})

// Source Sans 3 for body copy — a humanist companion with a taller x-height
// than Lexend at small sizes, which is where the explanatory text lives.
const sourceSans = Source_Sans_3({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-sans',
  display: 'swap',
})

const plexMono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-plex-mono',
  display: 'swap',
})

export const metadata: Metadata = {
  title: 'WSLVault',
  description: 'Multi-tenant secrets management',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning className={`${lexend.variable} ${sourceSans.variable} ${plexMono.variable}`}>
      <body>
        <ThemeProvider>
          <AuthProvider>
            <Providers>{children}</Providers>
          </AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  )
}
