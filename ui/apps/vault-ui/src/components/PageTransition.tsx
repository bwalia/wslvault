'use client'

import { usePathname } from 'next/navigation'
import { motion } from 'framer-motion'

/**
 * Content transition between routes.
 *
 * Keyed on the pathname so the new page mounts fresh and animates in. Without
 * a key React reconciles the two trees and the content swaps instantly, which
 * on a dense table page reads as a flicker rather than a navigation.
 *
 * Deliberately small: 8px of travel and 200ms. A page transition is the most
 * tempting place in an app to overdo motion, and it is also the one a user
 * sees most often — anything more theatrical becomes tiring by the twentieth
 * navigation. It exists to signal "this is a different place", not to perform.
 *
 * No exit animation. Next's App Router unmounts the old route before the new
 * one commits, so an exit variant would need AnimatePresence holding a copy of
 * a page that has already released its data. The rise-in alone reads as
 * continuous, and costs nothing.
 */
export function PageTransition({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()

  return (
    <motion.div
      key={pathname}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
    >
      {children}
    </motion.div>
  )
}
