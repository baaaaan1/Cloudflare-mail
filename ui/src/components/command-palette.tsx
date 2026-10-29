import * as React from "react"
import {
  AtSign,
  Braces,
  Copy,
  Inbox,
  LayoutDashboard,
  LogOut,
  Moon,
  Plus,
  RefreshCw,
  Route,
  Search,
  Send,
  Settings,
  Sun,
} from "lucide-react"
import { toast } from "sonner"

import { useCreateAddressDialog } from "@/components/create-address-context"
import { useTheme } from "@/components/theme-provider"
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog"
import { useLogout } from "@/hooks/use-logout"
import { useWorkspace } from "@/hooks/use-workspace"
import { copyText, localPartOf } from "@/lib/format"
import { navigate } from "@/lib/router"
import { cn } from "cn"

type Command = {
  id: string
  label: string
  group: string
  icon: React.ComponentType<{ className?: string }>
  keywords?: string
  hint?: string
  action: () => void
}

type CommandPaletteProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const { addresses, activeAddress, setActiveAddress, refreshWorkspace } = useWorkspace()
  const { open: openCreate } = useCreateAddressDialog()
  const { resolvedTheme, setTheme } = useTheme()
  const logout = useLogout()
  const [query, setQuery] = React.useState("")
  const [activeIndex, setActiveIndex] = React.useState(0)
  const listRef = React.useRef<HTMLDivElement>(null)

  const closeAnd = React.useCallback(
    (action: () => void) => {
      onOpenChange(false)
      window.setTimeout(action, 60)
    },
    [onOpenChange]
  )

  const commands = React.useMemo<Command[]>(() => {
    const navCommands: Command[] = [
      { id: "nav-overview", label: "Go to Overview", group: "Navigate", icon: LayoutDashboard, action: () => navigate("/") },
      { id: "nav-inbox", label: "Go to Inbox", group: "Navigate", icon: Inbox, action: () => navigate("/inbox") },
      { id: "nav-addresses", label: "Go to Addresses", group: "Navigate", icon: AtSign, action: () => navigate("/addresses") },
      { id: "nav-rules", label: "Go to Routing rules", group: "Navigate", icon: Route, action: () => navigate("/rules") },
      { id: "nav-destinations", label: "Go to Destinations", group: "Navigate", icon: Send, action: () => navigate("/destinations") },
      { id: "nav-docs", label: "Go to API docs", group: "Navigate", icon: Braces, keywords: "rest key developer", action: () => navigate("/docs") },
      { id: "nav-settings", label: "Go to Settings", group: "Navigate", icon: Settings, action: () => navigate("/settings") },
    ]

    const actions: Command[] = [
      {
        id: "create",
        label: "Create a new address",
        group: "Actions",
        icon: Plus,
        keywords: "new mailbox alias random",
        action: () => openCreate(),
      },
      {
        id: "refresh",
        label: "Refresh workspace",
        group: "Actions",
        icon: RefreshCw,
        keywords: "reload sync",
        action: () => {
          void refreshWorkspace()
          toast.success("Workspace refreshed")
        },
      },
      {
        id: "theme",
        label: resolvedTheme === "dark" ? "Switch to light theme" : "Switch to dark theme",
        group: "Actions",
        icon: resolvedTheme === "dark" ? Sun : Moon,
        keywords: "appearance dark light mode",
        action: () => setTheme(resolvedTheme === "dark" ? "light" : "dark"),
      },
    ]

    if (activeAddress) {
      actions.push({
        id: "copy-active",
        label: "Copy active address",
        group: "Actions",
        icon: Copy,
        keywords: "clipboard email",
        hint: activeAddress,
        action: () => {
          void copyText(activeAddress)
            .then(() => toast.success("Address copied"))
            .catch(() => toast.error("Could not copy address"))
        },
      })
    }

    actions.push({
      id: "logout",
      label: "Sign out",
      group: "Session",
      icon: LogOut,
      keywords: "logout exit",
      action: () => logout.mutate(),
    })

    const mailboxCommands: Command[] = addresses.slice(0, 6).map((mailbox) => ({
      id: `mailbox-${mailbox.address}`,
      label: `Open ${mailbox.address}`,
      group: "Mailboxes",
      icon: Inbox,
      keywords: `${mailbox.localPart} ${mailbox.domain}`,
      hint: `${mailbox.total} messages`,
      action: () => {
        setActiveAddress(mailbox.address)
        navigate("/inbox")
      },
    }))

    return [...navCommands, ...actions, ...mailboxCommands]
  }, [
    activeAddress,
    addresses,
    logout,
    openCreate,
    refreshWorkspace,
    resolvedTheme,
    setActiveAddress,
    setTheme,
  ])

  const filtered = React.useMemo(() => {
    const term = query.trim().toLowerCase()
    if (!term) return commands
    return commands.filter((command) =>
      `${command.label} ${command.group} ${command.keywords || ""}`.toLowerCase().includes(term)
    )
  }, [commands, query])

  React.useEffect(() => {
    if (!open) return
    setQuery("")
    setActiveIndex(0)
  }, [open])

  React.useEffect(() => {
    setActiveIndex((current) => Math.min(current, Math.max(filtered.length - 1, 0)))
  }, [filtered.length])

  React.useEffect(() => {
    const item = listRef.current?.querySelector<HTMLElement>(
      `[data-command-index="${activeIndex}"]`
    )
    item?.scrollIntoView({ block: "nearest" })
  }, [activeIndex])

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === "ArrowDown") {
      event.preventDefault()
      setActiveIndex((current) => (current + 1) % Math.max(filtered.length, 1))
    } else if (event.key === "ArrowUp") {
      event.preventDefault()
      setActiveIndex((current) =>
        (current - 1 + Math.max(filtered.length, 1)) % Math.max(filtered.length, 1)
      )
    } else if (event.key === "Enter") {
      event.preventDefault()
      const command = filtered[activeIndex]
      if (command) closeAnd(command.action)
    }
  }

  let lastGroup = ""

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        showCloseButton={false}
        className="top-[10%] max-w-[calc(100%-1.5rem)] translate-y-0 gap-0 overflow-hidden p-0 sm:max-w-xl"
        onKeyDown={handleKeyDown}
      >
        <DialogTitle className="sr-only">Command palette</DialogTitle>
        <DialogDescription className="sr-only">
          Search for pages, actions, or mailboxes.
        </DialogDescription>

        <div className="flex items-center gap-2.5 border-b border-border/70 px-4">
          <Search className="size-4 shrink-0 text-muted-foreground" />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search pages, actions, mailboxes…"
            className="h-12 min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
            autoFocus
            aria-label="Search commands"
            aria-activedescendant={
              filtered[activeIndex] ? `command-${filtered[activeIndex].id}` : undefined
            }
          />
          <kbd className="rounded-md border border-border bg-muted/60 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
            esc
          </kbd>
        </div>

        <div ref={listRef} className="max-h-[min(56vh,420px)] overflow-y-auto p-2 scrollbar-thin">
          {filtered.length === 0 && (
            <div className="px-4 py-10 text-center">
              <p className="text-sm font-medium">No results</p>
              <p className="mt-1 text-xs text-muted-foreground">
                Try a different keyword.
              </p>
            </div>
          )}

          {filtered.map((command, index) => {
            const showGroup = command.group !== lastGroup
            lastGroup = command.group
            const Icon = command.icon
            return (
              <React.Fragment key={command.id}>
                {showGroup && (
                  <p className="px-2 pt-3 pb-1.5 text-[10px] font-semibold tracking-[0.14em] text-muted-foreground uppercase">
                    {command.group}
                  </p>
                )}
                <button
                  type="button"
                  id={`command-${command.id}`}
                  data-command-index={index}
                  onMouseEnter={() => setActiveIndex(index)}
                  onClick={() => closeAnd(command.action)}
                  className={cn(
                    "flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-[13px] transition-colors",
                    activeIndex === index
                      ? "bg-accent text-accent-foreground"
                      : "text-muted-foreground"
                  )}
                >
                  <Icon className="size-4 shrink-0" />
                  <span className="min-w-0 flex-1 truncate">{command.label}</span>
                  {command.hint && (
                    <span className="max-w-40 truncate text-[10px] text-muted-foreground">
                      {command.hint}
                    </span>
                  )}
                </button>
              </React.Fragment>
            )
          })}
        </div>

        <div className="flex items-center gap-3 border-t border-border/70 bg-muted/30 px-4 py-2 text-[10px] text-muted-foreground">
          <span className="inline-flex items-center gap-1">
            <kbd className="rounded border border-border bg-background/70 px-1">↑</kbd>
            <kbd className="rounded border border-border bg-background/70 px-1">↓</kbd>
            navigate
          </span>
          <span className="inline-flex items-center gap-1">
            <kbd className="rounded border border-border bg-background/70 px-1">↵</kbd>
            select
          </span>
          <span className="ml-auto truncate">
            {activeAddress ? localPartOf(activeAddress) : "All mailboxes"}
          </span>
        </div>
      </DialogContent>
    </Dialog>
  )
}
