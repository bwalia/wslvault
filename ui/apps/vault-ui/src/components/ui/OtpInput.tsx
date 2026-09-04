'use client'

import { useCallback, useEffect, useRef } from 'react'
import { cn } from '@/lib/utils'

/**
 * Six boxes for a six-digit code.
 *
 * A single text field with letter-spacing looked like a code field without
 * behaving like one: no indication of how many digits are wanted, no sense of
 * progress, and the caret could land anywhere in the string. Discrete boxes say
 * "six" before the user types anything.
 *
 * ## What it handles that a naive version does not
 *
 * - **Paste.** Nearly everyone copies the code out of their authenticator
 *   rather than reading it across. A paste into any box fills all six, so it
 *   does not matter which one has focus.
 * - **Backspace on an empty box** moves back and clears the previous one. The
 *   alternative — backspace doing nothing until you manually click left — is
 *   the single most irritating way to get this wrong.
 * - **Arrow keys and clicks** move between boxes, because people do correct a
 *   single digit rather than retyping all six.
 * - **`autocomplete="one-time-code"`** on the first box, so iOS and the
 *   password managers that offer TOTP can fill it.
 *
 * ## Auto-submit
 *
 * `onComplete` fires once the sixth digit lands. It is deliberately guarded on
 * the value it fired for: React can re-render for reasons unrelated to typing,
 * and submitting the same code twice against a TOTP endpoint burns the code and
 * fails the second attempt.
 */
export function OtpInput({
  value,
  onChange,
  onComplete,
  length = 6,
  disabled,
  autoFocus,
  ariaLabel = 'Authenticator code',
  invalid,
}: {
  value: string
  onChange: (next: string) => void
  onComplete?: (code: string) => void
  length?: number
  disabled?: boolean
  autoFocus?: boolean
  ariaLabel?: string
  invalid?: boolean
}) {
  const refs = useRef<Array<HTMLInputElement | null>>([])
  const fired = useRef<string | null>(null)

  const digits = value.split('').slice(0, length)

  const focusBox = useCallback((i: number) => {
    const el = refs.current[Math.max(0, Math.min(i, length - 1))]
    el?.focus()
    el?.select()
  }, [length])

  // Fire once per completed code. Resetting when the value shortens is what
  // lets a user clear a rejected code and have the next one submit.
  useEffect(() => {
    if (value.length < length) {
      fired.current = null
      return
    }
    if (fired.current === value) return
    fired.current = value
    onComplete?.(value)
  }, [value, length, onComplete])

  const setDigit = (index: number, digit: string) => {
    const next = value.padEnd(length, ' ').split('')
    next[index] = digit || ' '
    onChange(next.join('').replace(/ +$/, '').replace(/ /g, ''))
  }

  return (
    <div
      className="flex items-center gap-2 sm:gap-2.5"
      role="group"
      aria-label={ariaLabel}
    >
      {Array.from({ length }, (_, i) => (
        <input
          key={i}
          ref={el => {
            refs.current[i] = el
          }}
          // `text`, not `number`: number renders spinners and drops a leading
          // zero, and a code can start with one.
          type="text"
          inputMode="numeric"
          autoComplete={i === 0 ? 'one-time-code' : 'off'}
          // Focused on mount when asked. This is the only thing to do on the
          // screens it appears on, and not focusing it costs every user a click
          // before they can type the code they are already holding.
          autoFocus={autoFocus && i === 0}
          disabled={disabled}
          aria-label={`Digit ${i + 1} of ${length}`}
          aria-invalid={invalid || undefined}
          value={digits[i] ?? ''}
          onChange={e => {
            // Long input here means a paste, or a keyboard that batches: take
            // the digits and fill forward from this box.
            const raw = e.target.value.replace(/\D/g, '')
            if (!raw) {
              setDigit(i, '')
              return
            }
            if (raw.length === 1) {
              setDigit(i, raw)
              if (i < length - 1) focusBox(i + 1)
              return
            }
            const merged = (value.slice(0, i) + raw).slice(0, length)
            onChange(merged)
            focusBox(merged.length)
          }}
          onKeyDown={e => {
            if (e.key === 'Backspace') {
              if (digits[i]) {
                setDigit(i, '')
                return
              }
              e.preventDefault()
              setDigit(i - 1, '')
              focusBox(i - 1)
            } else if (e.key === 'ArrowLeft') {
              e.preventDefault()
              focusBox(i - 1)
            } else if (e.key === 'ArrowRight') {
              e.preventDefault()
              focusBox(i + 1)
            }
          }}
          onPaste={e => {
            e.preventDefault()
            const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, length)
            if (!pasted) return
            onChange(pasted)
            focusBox(pasted.length)
          }}
          onFocus={e => e.currentTarget.select()}
          className={cn(
            'w-11 h-14 sm:w-12 sm:h-16 rounded-xl border bg-surface text-center',
            'font-mono text-2xl text-ink tabular-nums',
            'transition-colors duration-150',
            'focus:outline-none focus:border-brass focus:ring-4 focus:ring-brass/15',
            'disabled:opacity-50 disabled:cursor-not-allowed',
            invalid ? 'border-danger-500' : 'border-line-strong',
          )}
        />
      ))}
    </div>
  )
}
