'use client'

import { motion, useReducedMotion } from 'framer-motion'
import { ShieldCheck } from 'lucide-react'

/**
 * The vault opening — what a successful sign-in looks like.
 *
 * The mirror of {@link VaultDoor}: bolts retract, the dial spins back, the door
 * splits and swings apart, and light comes through the gap. Where the login
 * mark says "this is sealed", this says "it is open, come in", and then it gets
 * out of the way.
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

export function VaultOpening() {
  const reduced = useReducedMotion()

  const ease = [0.16, 1, 0.3, 1] as const

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
      <span className="sr-only">Signed in. Opening your vault.</span>

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
            initial={{ opacity: 0, scale: 0.7 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: reduced ? 0 : 0.85, duration: 0.8, ease }}
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
              initial={{ x: 0 }}
              animate={{ x: reduced ? 0 : dir * 130 }}
              transition={{ delay: reduced ? 0 : 0.75, duration: 0.9, ease }}
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
                    initial={{ cx: out.x, cy: out.y }}
                    animate={{ cx: reduced ? out.x : inn.x, cy: reduced ? out.y : inn.y }}
                    transition={{ delay: reduced ? 0 : 0.15 + i * 0.03, duration: 0.35, ease }}
                  />
                )
              })}

              {/* Dial, spinning back the other way */}
              <motion.g
                initial={{ rotate: 0 }}
                animate={{ rotate: reduced ? 0 : 260 }}
                transition={{ delay: reduced ? 0 : 0.05, duration: 0.75, ease }}
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
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: reduced ? 0.05 : 1.15, duration: 0.4, ease }}
        >
          <ShieldCheck className="w-10 h-10 text-accent-400" aria-hidden="true" />
          <p className="font-display text-lg font-semibold text-white">Vault unlocked</p>
          <p className="text-sm text-steel-ink">Taking you inside…</p>
        </motion.div>
      </div>
    </motion.div>
  )
}
