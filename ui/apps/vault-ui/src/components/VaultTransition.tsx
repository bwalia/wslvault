'use client'

import { motion, useReducedMotion } from 'framer-motion'
import { ShieldCheck, Lock } from 'lucide-react'

/**
 * The vault opening, or closing — the transition at both ends of a session.
 *
 * One component with a direction rather than two, because it is the same door.
 * Two components would drift: someone would restyle the bolts on one and not
 * the other, and signing out would stop looking like the reverse of signing in.
 *
 * `opening` runs on a successful sign-in — bolts retract, the dial spins back,
 * the halves swing apart, light comes through the gap. `closing` runs on
 * sign-out and is the same choreography backwards: the halves swing shut, the
 * dial turns, the bolts throw, and the light is cut off.
 *
 * ## Why it earns the ~1.5s it costs
 *
 * Normally a transition this long is a cost, not a feature. Here the user has
 * just typed a secret key and a one-time code and is being handed access to
 * every credential their organisation owns — a beat of acknowledgement is
 * proportionate, and it covers the dashboard's first data fetch, which is
 * otherwise a stretch of empty skeletons.
 *
 * It runs once per sign-in and never repeats. Under reduced motion the whole
 * thing collapses to a short fade: the message is "you are in", and the
 * choreography was only ever how that was said.
 */

const DOOR_R = 96

export type VaultDirection = 'opening' | 'closing'

export function VaultTransition({ direction }: { direction: VaultDirection }) {
  const reduced = useReducedMotion()
  const opening = direction === 'opening'

  const ease = [0.16, 1, 0.3, 1] as const

  /** Closing runs the same beats in reverse order. */
  const at = (openDelay: number, closeDelay: number) =>
    reduced ? 0 : opening ? openDelay : closeDelay

  return (
    <motion.div
      // Covers the whole viewport: this is a transition between two places,
      // and leaving the form visible underneath would undercut it.
      className="fixed inset-0 z-[100] flex items-center justify-center bg-steel"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.2 }}
      role="status"
      aria-live="polite"
    >
      <span className="sr-only">
        {opening ? 'Signed in. Opening your vault.' : 'Signing out. Sealing your vault.'}
      </span>

      <div className="relative">
        <svg viewBox="0 0 240 240" className="w-64 h-64 md:w-80 md:h-80" fill="none">
          <defs>
            {/* The light behind the door. Only visible once the halves part. */}
            <radialGradient id="vault-glow">
              <stop offset="0%" stopColor="#34d399" stopOpacity="0.55" />
              <stop offset="60%" stopColor="#059669" stopOpacity="0.15" />
              <stop offset="100%" stopColor="#059669" stopOpacity="0" />
            </radialGradient>
            {/* Each half is clipped to its own side of the frame, so they read
                as two leaves of one door rather than two separate shapes. */}
            <clipPath id="half-left">
              <rect x="0" y="0" width="120" height="240" />
            </clipPath>
            <clipPath id="half-right">
              <rect x="120" y="0" width="120" height="240" />
            </clipPath>
          </defs>

          {/* Interior light, revealed as the halves separate */}
          <motion.circle
            cx="120"
            cy="120"
            r="110"
            fill="url(#vault-glow)"
            initial={{ opacity: opening ? 0 : 1, scale: opening ? 0.7 : 1 }}
            animate={{ opacity: opening ? 1 : 0, scale: opening ? 1 : 0.75 }}
            transition={{ delay: at(0.85, 0.5), duration: 0.7, ease }}
            style={{ transformOrigin: '120px 120px' }}
          />

          {/* Frame */}
          <circle cx="120" cy="120" r="108" className="fill-steel" />
          <circle cx="120" cy="120" r="108" className="stroke-steel-line" strokeWidth="2" />

          {[
            { id: 'half-left', dir: -1 },
            { id: 'half-right', dir: 1 },
          ].map(({ id, dir }) => (
            <motion.g
              key={id}
              clipPath={`url(#${id})`}
              initial={{ x: opening ? 0 : dir * 130 }}
              animate={{ x: reduced ? 0 : opening ? dir * 130 : 0 }}
              transition={{ delay: at(0.75, 0.05), duration: 0.8, ease }}
            >
              <circle cx="120" cy="120" r={DOOR_R} className="fill-steel-raised" />
              <circle
                cx="120"
                cy="120"
                r={DOOR_R}
                className="stroke-steel-line"
                strokeWidth="2"
              />
              <circle
                cx="120"
                cy="120"
                r="80"
                className="stroke-steel-line"
                strokeWidth="1.5"
                strokeDasharray="3 6"
                opacity="0.5"
              />

              {/* Bolts, retracting before the door can move */}
              {[0, 60, 120, 180, 240, 300].map((angle, i) => {
                const rad = (angle * Math.PI) / 180
                const out = { x: 120 + Math.cos(rad) * 88, y: 120 + Math.sin(rad) * 88 }
                const inn = { x: 120 + Math.cos(rad) * 70, y: 120 + Math.sin(rad) * 70 }
                return (
                  <motion.circle
                    key={angle}
                    r="5"
                    className="fill-brass"
                    initial={{ cx: opening ? out.x : inn.x, cy: opening ? out.y : inn.y }}
                    animate={{
                      cx: reduced ? out.x : opening ? inn.x : out.x,
                      cy: reduced ? out.y : opening ? inn.y : out.y,
                    }}
                    transition={{
                      delay: at(0.15 + i * 0.03, 0.95 + i * 0.03),
                      duration: 0.35,
                      ease,
                    }}
                  />
                )
              })}

              {/* Dial, spinning back the other way */}
              <motion.g
                initial={{ rotate: opening ? 0 : 260 }}
                animate={{ rotate: reduced ? 0 : opening ? 260 : 0 }}
                transition={{ delay: at(0.05, 0.7), duration: 0.75, ease }}
                style={{ transformOrigin: '120px 120px' }}
              >
                <circle cx="120" cy="120" r="36" className="fill-steel" />
                <circle cx="120" cy="120" r="36" className="stroke-brass" strokeWidth="2.5" />
                {[0, 45, 90, 135].map(a => {
                  const rad = (a * Math.PI) / 180
                  return (
                    <line
                      key={a}
                      x1={120 + Math.cos(rad) * 24}
                      y1={120 + Math.sin(rad) * 24}
                      x2={120 - Math.cos(rad) * 24}
                      y2={120 - Math.sin(rad) * 24}
                      className="stroke-brass-dim"
                      strokeWidth="3.5"
                      strokeLinecap="round"
                    />
                  )
                })}
                <circle cx="120" cy="120" r="9" className="fill-brass" />
              </motion.g>
            </motion.g>
          ))}
        </svg>

        {/* The confirmation, arriving through the opened door */}
        <motion.div
          className="absolute inset-0 flex flex-col items-center justify-center gap-3"
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: opening ? 1 : 0, scale: 1 }}
          transition={{ delay: at(1.15, 0), duration: 0.4, ease }}
        >
          <ShieldCheck className="w-10 h-10 text-accent-400" aria-hidden="true" />
          <p className="font-display text-lg font-semibold text-white">Vault unlocked</p>
          <p className="text-sm text-steel-ink">Taking you inside…</p>
        </motion.div>

        {/* Closing says the opposite, and says it in brass rather than green —
            green is reserved for "open". */}
        <motion.div
          className="absolute inset-0 flex flex-col items-center justify-center gap-3"
          initial={{ opacity: 0 }}
          animate={{ opacity: opening ? 0 : 1 }}
          transition={{ delay: at(0, 1.25), duration: 0.4, ease }}
        >
          <Lock className="w-10 h-10 text-brass" aria-hidden="true" />
          <p className="font-display text-lg font-semibold text-white">Vault sealed</p>
          <p className="text-sm text-steel-ink">You have been signed out.</p>
        </motion.div>
      </div>
    </motion.div>
  )
}
