'use client'

import { Lock } from 'lucide-react'
import { motion } from 'framer-motion'

import BuildStamp from '@/components/BuildStamp'
import { VaultDoor } from '@/components/VaultDoor'
import { ParticleField } from '@/components/ParticleField'
import { stagger, staggerItem } from '@/lib/motion'

/**
 * The steel panel that sits beside every signed-out screen.
 *
 * Extracted so sign-in and the invitation wizard are visibly the same product.
 * The invitation page used to be a centred white card with navy accents while
 * the login screen was brass-on-steel — a new user's *first* impression was of
 * a different application to the one they were being let into.
 *
 * Render it from a layout, never from a page: a layout is not re-rendered when
 * its children change, so the door's locking sequence survives navigation
 * between steps. Mounted in a page, the door would re-lock itself every time
 * the user made progress — distracting, and backwards.
 *
 * The headline is a prop because the two flows are saying different things. The
 * furniture around it is not, because they are the same door.
 */
export function VaultPanel({
  headline,
  lede,
}: {
  headline: React.ReactNode
  lede: React.ReactNode
}) {
  return (
    // Hidden below lg: on a phone this would be a screen of decoration between
    // the user and the form they came for.
    //
    // The mark and the footprint stay in their corners — a wordmark belongs at
    // the top-left of the panel, not floating in the middle of it. Only the
    // hero centres, which is what fills a wide monitor: at 2500px the whole
    // block used to sit against the left padding edge with the rest of the
    // panel empty beside it.
    <div className="hidden lg:flex flex-col justify-between bg-steel px-10 py-12 xl:py-16 relative overflow-hidden">
      <ParticleField />

      {/* Rings: depth without a texture file, and they anchor the particles to
          something rather than leaving them drifting in a void.

          Centred on the panel rather than hung off its right edge — pinned
          right they were mostly outside the panel on a wide screen, reading as
          two unexplained arcs instead of as a target the door sits inside. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-[44rem] h-[44rem] rounded-full border border-steel-line opacity-30"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-[32rem] h-[32rem] rounded-full border border-steel-line opacity-25"
      />

      <div className="flex items-center gap-3 relative">
        <div className="w-9 h-9 rounded-lg bg-primary-700 flex items-center justify-center ring-1 ring-brass/30">
          <Lock className="w-[18px] h-[18px] text-brass" aria-hidden="true" />
        </div>
        <span className="font-display text-lg font-semibold tracking-tight text-white">
          WSL<span className="text-brass">Vault</span>
        </span>
      </div>

      <motion.div
        variants={stagger}
        initial="hidden"
        animate="visible"
        className="w-full max-w-lg mx-auto relative py-10"
      >
        {/* The door grows with the panel. At a fixed 176px it was a small badge
            adrift in a very large dark rectangle on anything above 1600px. */}
        <motion.div variants={staggerItem} className="mb-10">
          <VaultDoor className="w-48 h-48 xl:w-60 xl:h-60 2xl:w-72 2xl:h-72" />
        </motion.div>

        <motion.h1
          variants={staggerItem}
          className="font-display text-[2.5rem] xl:text-[3rem] leading-[1.05] font-semibold tracking-tight text-white text-balance"
        >
          {headline}
        </motion.h1>

        <motion.p
          variants={staggerItem}
          className="mt-6 text-base xl:text-lg text-steel-ink max-w-md leading-relaxed"
        >
          {lede}
        </motion.p>
      </motion.div>

      <div className="relative">
        <p className="font-mono text-xs text-steel-ink-dim">
          AES-256-GCM · per-tenant KEK · multi-region
        </p>
        <BuildStamp className="mt-1.5 text-xs" />
      </div>
    </div>
  )
}
