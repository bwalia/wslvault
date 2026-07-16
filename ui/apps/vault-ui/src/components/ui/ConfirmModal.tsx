'use client'
import { useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { Modal } from './Modal'
import { Button } from './Button'
import { Input } from './Input'

interface ConfirmModalProps {
  open: boolean
  onClose(): void
  onConfirm(): void | Promise<void>
  title: string
  description: string
  /** If provided, user must type this value to confirm */
  confirmText?: string
  confirmLabel?: string
  danger?: boolean
  loading?: boolean
  /**
   * Error from the confirmed action, rendered inside the modal.
   *
   * A destructive action that fails leaves the modal open. If the caller
   * renders the error on the page behind it, the modal backdrop covers it and
   * the user sees the spinner stop with no explanation — indistinguishable
   * from the action silently doing nothing. The error has to live in here.
   */
  error?: string
}

export function ConfirmModal({
  open,
  onClose,
  onConfirm,
  title,
  description,
  confirmText,
  confirmLabel = 'Confirm',
  danger = true,
  loading = false,
  error = '',
}: ConfirmModalProps) {
  const [typed, setTyped] = useState('')

  const canConfirm = confirmText ? typed === confirmText : true

  const handleConfirm = async () => {
    try {
      await onConfirm()
    } catch (err) {
      // Callers are expected to guard internally (useAsyncAction) and pass
      // `error` back in. This is a backstop so a caller that doesn't cannot
      // produce an unhandled rejection here.
      console.error('[ConfirmModal] onConfirm rejected:', err)
      return
    }
    setTyped('')
  }

  const handleClose = () => {
    setTyped('')
    onClose()
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={title}
      size="sm"
      footer={
        <>
          <Button variant="secondary" size="sm" onClick={handleClose} disabled={loading}>
            Cancel
          </Button>
          <Button
            variant={danger ? 'danger' : 'primary'}
            size="sm"
            onClick={handleConfirm}
            disabled={!canConfirm}
            loading={loading}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="flex gap-3">
        <AlertTriangle
          className="w-5 h-5 shrink-0 mt-0.5 text-danger-600 dark:text-danger-400"
          aria-hidden="true"
        />
        <div className="flex-1">
          <p className="text-sm text-ink leading-relaxed">{description}</p>
          {confirmText && (
            <div className="mt-4">
              <p className="text-xs text-ink-muted mb-2">
                Type <span className="font-mono font-semibold text-ink">{confirmText}</span> to
                confirm — this cannot be undone.
              </p>
              <Input
                value={typed}
                onChange={e => setTyped(e.target.value)}
                placeholder={confirmText}
                mono
                size={undefined}
              />
            </div>
          )}
          {error && (
            <p
              role="alert"
              className="mt-3 rounded-lg border border-danger-600/30 bg-danger-600/5 px-2.5 py-2 text-xs text-danger-600"
            >
              {error}
            </p>
          )}
        </div>
      </div>
    </Modal>
  )
}
