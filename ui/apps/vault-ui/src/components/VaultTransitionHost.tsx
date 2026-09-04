'use client'

import { AnimatePresence } from 'framer-motion'
import { useAuth } from '@/contexts/AuthContext'
import { VaultTransition } from '@/components/VaultTransition'

/**
 * Renders the vault transition wherever the user happens to be.
 *
 * Mounted at the app root rather than in a layout, because the two ends of a
 * session start from different places: signing in from `(auth)`, signing out
 * from the dashboard. Putting it in the auth layout meant sign-out had nothing
 * to render into until the navigation had already happened — by which point
 * there was nothing left to cover.
 */
export function VaultTransitionHost() {
  const { vaultTransition } = useAuth()
  return (
    <AnimatePresence>
      {vaultTransition && (
        <VaultTransition key={vaultTransition} direction={vaultTransition} />
      )}
    </AnimatePresence>
  )
}
