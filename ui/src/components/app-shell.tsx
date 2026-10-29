import * as React from "react"
import { AnimatePresence, motion, useReducedMotion } from "motion/react"
import { Command } from "lucide-react"

import { CommandPalette } from "@/components/command-palette"
import { useCreateAddressDialog } from "@/components/create-address-context"
import { MobileNav } from "@/components/mobile-nav"
import { Sidebar } from "@/components/sidebar"
import { Topbar } from "@/components/topbar"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetTitle,
} from "@/components/ui/sheet"
import { useKeyboardShortcut } from "@/hooks/use-keyboard-shortcut"
import { AddressesPage } from "@/pages/addresses"
import { ApiDocsPage } from "@/pages/api-docs"
import { DestinationsPage } from "@/pages/destinations"
import { InboxPage } from "@/pages/inbox"
import { OverviewPage } from "@/pages/overview"
import { RulesPage } from "@/pages/rules"
import { SettingsPage } from "@/pages/settings"
import { useRoute } from "@/lib/router"

const PAGES: Record<string, React.ComponentType> = {
  overview: OverviewPage,
  inbox: InboxPage,
  addresses: AddressesPage,
  rules: RulesPage,
  destinations: DestinationsPage,
  docs: ApiDocsPage,
  settings: SettingsPage,
}

function isEditableTarget(target: EventTarget | null) {
  return (
    target instanceof HTMLElement &&
    Boolean(target.closest("input, textarea, select, [contenteditable='true']"))
  )
}

export function AppShell() {
  const [menuOpen, setMenuOpen] = React.useState(false)
  const [commandOpen, setCommandOpen] = React.useState(false)
  const { section } = useRoute()
  const { open: openCreate } = useCreateAddressDialog()
  const prefersReducedMotion = useReducedMotion()

  const Page = PAGES[section] ?? OverviewPage

  useKeyboardShortcut({ key: "k", meta: true }, (event) => {
    event.preventDefault()
    setCommandOpen((current) => !current)
  })

  useKeyboardShortcut(
    { key: "n" },
    (event) => {
      if (isEditableTarget(event.target)) return
      event.preventDefault()
      openCreate()
    },
    { enabled: !commandOpen }
  )

  return (
    <div className="relative min-h-svh">
      <div className="app-backdrop" />

      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:rounded-lg focus:bg-primary focus:px-3 focus:py-2 focus:text-sm focus:text-primary-foreground"
      >
        Skip to content
      </a>

      <div className="lg:grid lg:min-h-svh lg:grid-cols-[17rem_minmax(0,1fr)]">
        <aside className="sticky top-0 hidden h-svh border-r border-sidebar-border lg:block">
          <Sidebar />
        </aside>

        <div className="flex min-h-svh min-w-0 flex-col">
          <Topbar
            onOpenMenu={() => setMenuOpen(true)}
            onOpenCommand={() => setCommandOpen(true)}
          />

          <main
            id="main-content"
            className="flex-1 px-4 pt-6 pb-28 sm:px-6 lg:px-8 lg:pt-8 lg:pb-10"
          >
            <div className="mx-auto w-full max-w-[1440px]">
              <AnimatePresence mode="wait" initial={false}>
                <motion.div
                  key={section}
                  initial={prefersReducedMotion ? false : { opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={prefersReducedMotion ? undefined : { opacity: 0, y: -6 }}
                  transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
                >
                  <Page />
                </motion.div>
              </AnimatePresence>
            </div>
          </main>

          <footer className="hidden items-center justify-between px-8 pb-5 text-[10px] text-muted-foreground lg:flex">
            <span>Cloudflare Email Panel · self-hosted</span>
            <span className="inline-flex items-center gap-1">
              <Command className="size-3" />
              K to jump anywhere
            </span>
          </footer>
        </div>
      </div>

      <MobileNav />

      <Sheet open={menuOpen} onOpenChange={setMenuOpen}>
        <SheetContent
          side="left"
          className="w-[18rem] max-w-[85vw] gap-0 border-sidebar-border bg-sidebar p-0"
        >
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <SheetDescription className="sr-only">
            Workspace navigation and mailboxes.
          </SheetDescription>
          <Sidebar
            onNavigate={() => setMenuOpen(false)}
            layoutIdPrefix="mobile"
            className="bg-transparent"
          />
        </SheetContent>
      </Sheet>

      <CommandPalette open={commandOpen} onOpenChange={setCommandOpen} />
    </div>
  )
}
