import { VaultPanel } from '@/components/VaultPanel'

/**
 * Shell for the invitation wizard.
 *
 * Same furniture as sign-in, different words. Someone opening an invitation has
 * never seen this product; the panel's job here is to say what they are being
 * let into, not to welcome them back.
 *
 * It is a layout rather than markup inside the page for the usual reason — the
 * wizard swaps its whole body seven times, and the door should not re-lock
 * itself at every step.
 */
export default function InviteLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen grid lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] bg-canvas">
      <VaultPanel
        headline={
          <>
            You have been
            <br />
            given a key to
            <br />
            <span className="text-brass">the vault.</span>
          </>
        }
        lede="A few short steps and you are in. Two of them show something you will only ever see once — have somewhere safe ready to put it."
      />
      <div className="flex items-center justify-center px-6 py-10 sm:px-10">{children}</div>
    </div>
  )
}
