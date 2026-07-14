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
}: ConfirmModalProps) {
  const [typed, setTyped] = useState('')

  const canConfirm = confirmText ? typed === confirmText : true

  const handleConfirm = async () => {
    await onConfirm()
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
          className="w-5 h-5 flex-shrink-0 mt-0.5 text-danger-600 dark:text-danger-400"
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
        </div>
      </div>
    </Modal>
  )
}
