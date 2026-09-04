'use client'

import { motion, useReducedMotion } from 'framer-motion'

/**
 * The vault door — the brand mark, drawn rather than decorated.
 *
 * Inline SVG for three reasons: it inherits `currentColor` so it themes with
 * the rest of the app, it stays crisp at any size, and it is the one element
 * that can carry the locker idea without a stock illustration. An `<img>` here
 * would need a light and a dark copy and would still be a picture of a vault
 * rather than part of the interface.
 *
 * The dial turns once on mount and the bolts seat as it finishes. That is the
 * whole animation: it says "this is sealed" and then stops. A door that keeps
 * turning reads as a loading spinner, which is the opposite of the message.
 */
export function VaultDoor({ className = '' }: { className?: string }) {
  const reduced = useReducedMotion()

  return (
    <svg
      viewBox="0 0 200 200"
      className={className}
      fill="none"
      role="img"
      aria-label="A closed vault door"
    >
      {/* Door plate */}
      <circle cx="100" cy="100" r="86" className="fill-steel-raised" />
      <circle
        cx="100"
        cy="100"
        r="86"
        className="stroke-steel-line"
        strokeWidth="2"
      />
      <circle
        cx="100"
        cy="100"
        r="72"
        className="stroke-steel-line"
        strokeWidth="1.5"
        strokeDasharray="3 6"
        opacity="0.7"
      />

      {/* Bolts around the rim. Seated last, so the door reads as locking. */}
      {[0, 60, 120, 180, 240, 300].map((angle, i) => {
        const rad = (angle * Math.PI) / 180
        const x = 100 + Math.cos(rad) * 79
        const y = 100 + Math.sin(rad) * 79
        return (
          <motion.circle
            key={angle}
            cx={x}
            cy={y}
            r="4.5"
            className="fill-brass"
            initial={reduced ? { opacity: 1 } : { opacity: 0, scale: 0.4 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{
              delay: reduced ? 0 : 0.55 + i * 0.05,
              duration: 0.25,
              ease: [0.16, 1, 0.3, 1],
            }}
            style={{ transformOrigin: `${x}px ${y}px` }}
          />
        )
      })}

      {/* The dial. One turn, then still. */}
      <motion.g
        initial={reduced ? { rotate: 0 } : { rotate: -140 }}
        animate={{ rotate: 0 }}
        transition={{ duration: reduced ? 0 : 0.9, ease: [0.16, 1, 0.3, 1] }}
        style={{ transformOrigin: '100px 100px' }}
      >
        <circle cx="100" cy="100" r="34" className="fill-steel" />
        <circle
          cx="100"
          cy="100"
          r="34"
          className="stroke-brass"
          strokeWidth="2.5"
        />
        {/* Spokes */}
        {[0, 45, 90, 135].map(a => (
          <line
            key={a}
            x1={100 + Math.cos((a * Math.PI) / 180) * 30}
            y1={100 + Math.sin((a * Math.PI) / 180) * 30}
            x2={100 - Math.cos((a * Math.PI) / 180) * 30}
            y2={100 - Math.sin((a * Math.PI) / 180) * 30}
            className="stroke-brass-dim"
            strokeWidth="3"
            strokeLinecap="round"
          />
        ))}
        <circle cx="100" cy="100" r="8" className="fill-brass" />
      </motion.g>
    </svg>
  )
}
