import { VaultPanel } from '@/components/VaultPanel'

/**
 * Shell for the signed-out routes.
 *
 * The panel lives in the layout rather than the page so that moving between
 * steps leaves the vault mark mounted and its locking sequence undisturbed —
 * see [`VaultPanel`] for why that matters.
 */
export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen grid lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] bg-canvas">
      <VaultPanel
        headline={
          <>
            Your secrets,
            <br />
            behind a door
            <br />
            <span className="text-brass">only you open.</span>
          </>
        }
        lede="Every tenant gets its own key. Nothing is stored in the clear, and every read is written to an audit trail you can inspect."
      />
      <div className="flex items-center justify-center px-6 py-10 sm:px-10">{children}</div>
    </div>
  )
}
