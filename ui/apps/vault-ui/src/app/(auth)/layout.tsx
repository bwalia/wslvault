'use client'

import { Lock } from 'lucide-react'
import { motion } from 'framer-motion'

import BuildStamp from '@/components/BuildStamp'
import { VaultDoor } from '@/components/VaultDoor'
import { ParticleField } from '@/components/ParticleField'
import { stagger, staggerItem } from '@/lib/motion'

/**
 * Shell for the signed-out routes.
 *
 * The left panel lives here rather than in the page, which is the point: a
 * layout is not re-rendered when its children change, so moving between the
 * key step and the code step leaves the vault mark mounted and its locking
 * sequence undisturbed. Put it in the page and every step change would replay
 * the animation from the top — the door re-locking itself each time the user
 * makes progress, which is both distracting and backwards.
 *
 * It also means the panel does not flash between routes. Anything added here
 * later (a status banner, a region indicator) inherits that for free.
 */
export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen grid lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] bg-canvas">
      {/* Left — the vault. Hidden below lg: on a phone it would be a screen of
          decoration between the user and the form they came for. */}
      <div className="hidden lg:flex flex-col justify-between bg-steel p-10 relative overflow-hidden">
        <ParticleField />

        {/* Rings: depth without a texture file, and they anchor the particles
            to something rather than leaving them drifting in a void. */}
        <div
          aria-hidden="true"
          className="pointer-events-none absolute -right-32 top-1/2 -translate-y-1/2 w-[36rem] h-[36rem] rounded-full border border-steel-line opacity-40"
        />
        <div
          aria-hidden="true"
          className="pointer-events-none absolute -right-20 top-1/2 -translate-y-1/2 w-[26rem] h-[26rem] rounded-full border border-steel-line opacity-30"
        />

        <div className="flex items-center gap-3 relative">
          <div className="w-9 h-9 rounded-lg bg-primary-700 flex items-center justify-center ring-1 ring-brass/30">
            <Lock className="w-4.5 h-4.5 text-brass" aria-hidden="true" />
          </div>
          <span className="font-display text-lg font-semibold tracking-tight text-white">
            WSL<span className="text-brass">Vault</span>
          </span>
        </div>

        <motion.div variants={stagger} initial="hidden" animate="visible" className="relative">
          <motion.div variants={staggerItem} className="mb-10">
            <VaultDoor className="w-44 h-44 xl:w-52 xl:h-52" />
          </motion.div>

          <motion.h1
            variants={staggerItem}
            className="font-display text-[2.5rem] leading-[1.1] font-semibold tracking-tight text-white max-w-md text-balance"
          >
            Your secrets,
            <br />
            behind a door
            <br />
            <span className="text-brass">only you open.</span>
          </motion.h1>

          <motion.p
            variants={staggerItem}
            className="mt-5 text-base text-steel-ink max-w-sm leading-relaxed"
          >
            Every tenant gets its own key. Nothing is stored in the clear, and
            every read is written to an audit trail you can inspect.
          </motion.p>
        </motion.div>

        <div className="relative">
          <p className="font-mono text-xs text-steel-ink-dim">
            AES-256-GCM · per-tenant KEK · multi-region
          </p>
          <BuildStamp className="mt-1.5 text-xs" />
        </div>
      </div>

      {/* Right — whichever step the user is on */}
      <div className="flex items-center justify-center p-6">{children}</div>
    </div>
  )
}
