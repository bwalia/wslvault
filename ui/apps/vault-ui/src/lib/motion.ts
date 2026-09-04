'use client'

/**
 * Motion vocabulary for the vault.
 *
 * One file so every animation shares a rhythm. Scattering durations and easings
 * through components is how an interface ends up feeling like several
 * interfaces — one thing springs, another eases, a third snaps, and the whole
 * reads as unfinished.
 *
 * ## The rules these encode
 *
 * Durations sit in 150–300ms for micro-interactions and stay under 400ms for
 * anything larger. Motion is `transform` and `opacity` only: animating width,
 * height or top forces layout on every frame and drops the animation off the
 * compositor.
 *
 * Exits run at roughly 60% of their entrance. An interface that takes as long
 * to get out of the way as it took to arrive feels sluggish, even when the
 * numbers look symmetrical on paper.
 *
 * ## Reduced motion is honoured at the source
 *
 * Every variant here is filtered through {@link respectMotion}, so a user who
 * has asked their system for less motion gets opacity changes and nothing that
 * travels. That is handled once, here, rather than depending on each component
 * remembering a media query.
 */

import type { Transition, Variants } from 'framer-motion'

/** Whether this user has asked for less motion. Safe during SSR. */
export function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || !window.matchMedia) return false
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

/** Standard easing. `easeOut` for arrivals — quick to appear, gentle to settle. */
export const ease = {
  out: [0.16, 1, 0.3, 1],
  inOut: [0.65, 0, 0.35, 1],
} as const

export const duration = {
  /** Hover, press, colour changes. */
  fast: 0.15,
  /** The default: cards, panels, list items. */
  base: 0.24,
  /** Page and modal transitions. */
  slow: 0.36,
} as const

/**
 * Strip travel from a variant set when the user has asked for less motion.
 *
 * Deliberately keeps the opacity change: fading is not what causes vestibular
 * discomfort, and removing *all* feedback leaves someone unable to tell that
 * anything happened. Reduced motion means calmer, not absent.
 */
export function respectMotion(v: Variants): Variants {
  if (!prefersReducedMotion()) return v
  return {
    hidden: { opacity: 0 },
    visible: { opacity: 1, transition: { duration: duration.fast } },
    exit: { opacity: 0, transition: { duration: duration.fast } },
  }
}

/** A panel arriving: rises a little as it fades in. */
export const panel: Variants = {
  hidden: { opacity: 0, y: 12 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: duration.base, ease: ease.out },
  },
  exit: {
    opacity: 0,
    y: 6,
    // ~60% of the entrance. See the note at the top.
    transition: { duration: duration.fast, ease: ease.out },
  },
}

/**
 * A list revealing itself, one item after another.
 *
 * 40ms between children: below about 30ms the stagger is imperceptible and you
 * have paid for nothing; above about 60ms a ten-row table takes long enough
 * that the reader starts waiting for it.
 */
export const stagger: Variants = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.04, delayChildren: 0.04 } },
}

export const staggerItem: Variants = {
  hidden: { opacity: 0, y: 8 },
  visible: { opacity: 1, y: 0, transition: { duration: duration.base, ease: ease.out } },
}

/**
 * A modal or sheet, animating from its own centre.
 *
 * Scales from 0.96 rather than 0 — growing from nothing reads as an object
 * being created, where a dialog should read as an object being brought forward.
 */
export const dialog: Variants = {
  hidden: { opacity: 0, scale: 0.96, y: 8 },
  visible: {
    opacity: 1,
    scale: 1,
    y: 0,
    transition: { duration: duration.base, ease: ease.out },
  },
  exit: { opacity: 0, scale: 0.98, transition: { duration: duration.fast } },
}

/** The scrim behind a dialog. Fades only; it has no position to animate. */
export const scrim: Variants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { duration: duration.base } },
  exit: { opacity: 0, transition: { duration: duration.fast } },
}

/**
 * Press feedback for cards and buttons.
 *
 * Applied with `whileTap`. 0.97 rather than something more dramatic: the point
 * is to confirm the press registered, and a large scale on a wide element looks
 * like the layout broke rather than like a button responding.
 */
export const press = { scale: 0.97 } as const

/** Transition for a value that counts up, or a bar that fills. */
export const settle: Transition = {
  duration: duration.slow,
  ease: ease.out,
}
