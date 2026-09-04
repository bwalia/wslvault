'use client'

import { motion, useReducedMotion } from 'framer-motion'

/**
 * The vault door — the brand mark, drawn rather than decorated, and animated
 * as an actual locking sequence.
 *
 * Inline SVG rather than a GIF or an illustration. It inherits `currentColor`
 * so it themes with the rest of the app, stays crisp at any size, weighs
 * nothing, and can respect reduced motion — none of which a GIF can do. A GIF
 * would also need a light and a dark copy and would still be a picture of a
 * vault placed on the page rather than part of the interface.
 *
 * ## The choreography, and why it is in this order
 *
 * It follows how a real vault actually locks, because that is what makes it
 * read as locking rather than as a spinner:
 *
 *   1. the dial spins — a long turn that decelerates, the way a weighted
 *      wheel does
 *   2. the bolts THROW OUTWARD into the frame. This is the step that carries
 *      the meaning. Bolts that merely appear look like decoration; bolts that
 *      travel outward and stop are a door being secured
 *   3. a ring sweeps the rim, confirming the seal
 *   4. the brass settles brighter, and everything stops
 *
 * Then it holds. It does not loop: a door that keeps locking reads as a
 * loading spinner, which says "wait" where this needs to say "secured".
 */

/** Bolt seats, evenly spaced around the rim. */
const BOLT_ANGLES = [0, 60, 120, 180, 240, 300]

/** Where a bolt starts (retracted) and ends (thrown into the frame). */
const BOLT_IN = 62
const BOLT_OUT = 79

const RIM_RADIUS = 86
const RIM_CIRCUMFERENCE = 2 * Math.PI * RIM_RADIUS

export function VaultDoor({ className = '' }: { className?: string }) {
  const reduced = useReducedMotion()

  // With reduced motion the door is simply shown locked. The information is
  // "this is sealed"; the animation was only ever how that was said, so
  // removing it costs nothing a user needs.
  const t = (delay: number, duration: number) =>
    reduced ? { duration: 0 } : { delay, duration, ease: [0.16, 1, 0.3, 1] as const }

  return (
    <svg
      viewBox="0 0 200 200"
      className={className}
      fill="none"
      role="img"
      aria-label="A vault door closing and locking"
    >
      {/* Frame the bolts throw into */}
      <circle cx="100" cy="100" r="94" className="fill-steel" />
      <circle cx="100" cy="100" r="94" className="stroke-steel-line" strokeWidth="1.5" />

      {/* Door plate */}
      <circle cx="100" cy="100" r={RIM_RADIUS} className="fill-steel-raised" />
      <circle cx="100" cy="100" r={RIM_RADIUS} className="stroke-steel-line" strokeWidth="2" />
      <circle
        cx="100"
        cy="100"
        r="72"
        className="stroke-steel-line"
        strokeWidth="1.5"
        strokeDasharray="3 6"
        opacity="0.6"
      />

      {/* 3. The seal sweep. Drawn as a stroke revealing itself around the rim —
             rotated -90° so it starts at the top, where an eye expects it. */}
      <motion.circle
        cx="100"
        cy="100"
        r={RIM_RADIUS}
        className="stroke-accent-500"
        strokeWidth="3"
        strokeLinecap="round"
        strokeDasharray={RIM_CIRCUMFERENCE}
        initial={{ strokeDashoffset: reduced ? 0 : RIM_CIRCUMFERENCE, opacity: 0.9 }}
        animate={{ strokeDashoffset: 0, opacity: [0.9, 0.9, 0.35] }}
        transition={{
          strokeDashoffset: t(1.15, 0.7),
          opacity: { delay: reduced ? 0 : 1.85, duration: 0.5 },
        }}
        style={{ transformOrigin: '100px 100px', rotate: -90 }}
      />

      {/* 2. The bolts. `cx` travels outward — the locking action itself. */}
      {BOLT_ANGLES.map((angle, i) => {
        const rad = (angle * Math.PI) / 180
        const from = { x: 100 + Math.cos(rad) * BOLT_IN, y: 100 + Math.sin(rad) * BOLT_IN }
        const to = { x: 100 + Math.cos(rad) * BOLT_OUT, y: 100 + Math.sin(rad) * BOLT_OUT }
        return (
          <motion.g key={angle}>
            {/* The shaft, extending behind the head so the bolt reads as
                sliding out of the door rather than sprouting from nothing. */}
            <motion.line
              x1={from.x}
              y1={from.y}
              className="stroke-brass-dim"
              strokeWidth="5"
              strokeLinecap="round"
              initial={{ x2: from.x, y2: from.y }}
              animate={{ x2: to.x, y2: to.y }}
              transition={t(0.75 + i * 0.04, 0.4)}
            />
            <motion.circle
              r="5"
              className="fill-brass"
              initial={{ cx: from.x, cy: from.y, opacity: 0 }}
              animate={{ cx: to.x, cy: to.y, opacity: 1 }}
              transition={t(0.75 + i * 0.04, 0.4)}
            />
          </motion.g>
        )
      })}

      {/* 1. The dial. Nearly a full turn, decelerating like a weighted wheel. */}
      <motion.g
        initial={reduced ? { rotate: 0 } : { rotate: -330 }}
        animate={{ rotate: 0 }}
        transition={t(0.1, 1.0)}
        style={{ transformOrigin: '100px 100px' }}
      >
        <circle cx="100" cy="100" r="34" className="fill-steel" />
        <circle cx="100" cy="100" r="34" className="stroke-brass" strokeWidth="2.5" />

        {/* Notches, so the rotation is legible. Without them a smooth circle
            turns invisibly and the whole motion is wasted. */}
        {Array.from({ length: 12 }, (_, i) => i * 30).map(a => {
          const rad = (a * Math.PI) / 180
          return (
            <line
              key={a}
              x1={100 + Math.cos(rad) * 27}
              y1={100 + Math.sin(rad) * 27}
              x2={100 + Math.cos(rad) * 31}
              y2={100 + Math.sin(rad) * 31}
              className="stroke-brass-dim"
              strokeWidth="1.5"
              strokeLinecap="round"
            />
          )
        })}

        {/* Spokes */}
        {[0, 45, 90, 135].map(a => {
          const rad = (a * Math.PI) / 180
          return (
            <line
              key={a}
              x1={100 + Math.cos(rad) * 22}
              y1={100 + Math.sin(rad) * 22}
              x2={100 - Math.cos(rad) * 22}
              y2={100 - Math.sin(rad) * 22}
              className="stroke-brass-dim"
              strokeWidth="3.5"
              strokeLinecap="round"
            />
          )
        })}
        <circle cx="100" cy="100" r="9" className="fill-brass" />
      </motion.g>

      {/* 4. Seated. One brief brass flare as the seal completes, then nothing —
             the punctuation on the sequence, not an ongoing state. */}
      <motion.circle
        cx="100"
        cy="100"
        r={RIM_RADIUS}
        className="stroke-brass"
        strokeWidth="2"
        initial={{ opacity: 0 }}
        animate={reduced ? { opacity: 0.5 } : { opacity: [0, 0.85, 0.4] }}
        transition={{ delay: reduced ? 0 : 1.8, duration: 0.7 }}
      />
    </svg>
  )
}
