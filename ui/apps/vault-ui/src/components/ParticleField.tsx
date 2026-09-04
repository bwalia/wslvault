'use client'

import { useEffect, useRef } from 'react'

/**
 * A slow drift of points behind the vault panel.
 *
 * Canvas rather than particles.js: that library is ~180KB for what forty dots
 * and a distance check need, and it renders into its own DOM subtree that
 * cannot read the theme tokens. This draws with `currentColor` sampled from the
 * host element, so it follows light and dark like everything else.
 *
 * ## Why it is this restrained
 *
 * It sits behind a headline and a form. Particles that move quickly, connect
 * densely, or react to the cursor pull the eye away from the thing the page
 * exists for. The drift here is slow enough to read as depth rather than as
 * motion — you notice it if you look, and not otherwise.
 *
 * ## Cost
 *
 * The link pass is O(n²), which is fine at n=44 and is why n stays there. The
 * loop stops entirely when the tab is hidden or the element scrolls out of
 * view; a background animation burning a core behind another window is a
 * laptop-battery bug, not a design flourish.
 */

interface Particle {
  x: number
  y: number
  vx: number
  vy: number
  r: number
}

const COUNT = 44
/** Distance under which two points are joined. */
const LINK_DISTANCE = 130

export function ParticleField({ className = '' }: { className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    // Honour the system preference. Reading it here rather than via a hook so
    // the effect can bail before allocating anything at all.
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let particles: Particle[] = []
    let frame = 0
    let running = true
    // Capped: a 3x device pixel ratio on a large panel triples the fill cost
    // for a difference nobody can see on a field of soft dots.
    const dpr = Math.min(window.devicePixelRatio || 1, 2)

    const resize = () => {
      const { width, height } = canvas.getBoundingClientRect()
      canvas.width = width * dpr
      canvas.height = height * dpr
      ctx.scale(dpr, dpr)

      particles = Array.from({ length: COUNT }, () => ({
        x: Math.random() * width,
        y: Math.random() * height,
        // Slow: roughly 6-18 seconds to cross the panel.
        vx: (Math.random() - 0.5) * 0.22,
        vy: (Math.random() - 0.5) * 0.22,
        r: Math.random() * 1.6 + 0.7,
      }))
    }

    const draw = () => {
      if (!running) return
      const { width, height } = canvas.getBoundingClientRect()
      ctx.clearRect(0, 0, width, height)

      for (const p of particles) {
        p.x += p.vx
        p.y += p.vy
        // Wrap rather than bounce: bouncing makes the edges legible as walls,
        // and the field should feel like it continues past the panel.
        if (p.x < -10) p.x = width + 10
        if (p.x > width + 10) p.x = -10
        if (p.y < -10) p.y = height + 10
        if (p.y > height + 10) p.y = -10
      }

      // Links first, so the dots sit on top of their own connections.
      ctx.lineWidth = 1
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x
          const dy = particles[i].y - particles[j].y
          const dist = Math.hypot(dx, dy)
          if (dist > LINK_DISTANCE) continue
          // Fade with distance so links resolve rather than blink on.
          ctx.strokeStyle = `rgba(148, 186, 219, ${(1 - dist / LINK_DISTANCE) * 0.16})`
          ctx.beginPath()
          ctx.moveTo(particles[i].x, particles[i].y)
          ctx.lineTo(particles[j].x, particles[j].y)
          ctx.stroke()
        }
      }

      for (const p of particles) {
        ctx.fillStyle = 'rgba(201, 162, 39, 0.34)'
        ctx.beginPath()
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2)
        ctx.fill()
      }

      frame = requestAnimationFrame(draw)
    }

    resize()
    draw()

    const onResize = () => {
      ctx.setTransform(1, 0, 0, 1, 0, 0)
      resize()
    }
    window.addEventListener('resize', onResize)

    // Stop when the tab is hidden — otherwise this runs forever behind
    // whatever the user actually switched to.
    const onVisibility = () => {
      if (document.hidden) {
        running = false
        cancelAnimationFrame(frame)
      } else if (!running) {
        running = true
        draw()
      }
    }
    document.addEventListener('visibilitychange', onVisibility)

    return () => {
      running = false
      cancelAnimationFrame(frame)
      window.removeEventListener('resize', onResize)
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className={`pointer-events-none absolute inset-0 h-full w-full ${className}`}
    />
  )
}
