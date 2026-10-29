import * as React from "react"
import {
  AtSign,
  Bookmark,
  BookmarkPlus,
  Copy,
  Inbox,
  Mail,
  MoreHorizontal,
  Plus,
  Search,
  Sparkles,
  Trash2,
} from "lucide-react"
import { motion, useReducedMotion } from "motion/react"
import { toast } from "sonner"

import { useCreateAddressDialog } from "@/components/create-address-context"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"
import { StatCard } from "@/components/stat-card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useWorkspace } from "@/hooks/use-workspace"
import {
  copyText,
  formatRelativeTime,
  getInitials,
  normalizeAddress,
} from "@/lib/format"
import { navigate } from "@/lib/router"
import type { Mailbox } from "@/lib/types"
import { cn } from "cn"

export function AddressesPage() {
  const {
    addresses,
    savedAddresses,
    activeAddress,
    setActiveAddress,
    addSavedAddress,
    removeSavedAddress,
    isAddressSaved,
    totalMessages,
    domains,
  } = useWorkspace()
  const { open } = useCreateAddressDialog()
  const prefersReducedMotion = useReducedMotion()

  const [search, setSearch] = React.useState("")
  const [trackOpen, setTrackOpen] = React.useState(false)
  const [trackValue, setTrackValue] = React.useState("")
  const [trackError, setTrackError] = React.useState("")

  const filtered = React.useMemo(() => {
    const term = search.trim().toLowerCase()
    if (!term) return addresses
    return addresses.filter((mailbox) => mailbox.address.includes(term))
  }, [addresses, search])

  const copyAddress = (address: string) => {
    void copyText(address)
      .then(() => toast.success("Address copied", { description: address }))
      .catch(() => toast.error("Could not copy address"))
  }

  const openMailbox = (mailbox: Mailbox) => {
    setActiveAddress(mailbox.address)
    navigate("/inbox")
  }

  const handleTrack = (event: React.FormEvent) => {
    event.preventDefault()
    const address = normalizeAddress(trackValue)
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)) {
      setTrackError("Enter a valid email address.")
      return
    }
    addSavedAddress(address)
    toast.success("Address tracked", { description: address })
    setTrackOpen(false)
    setTrackValue("")
    setTrackError("")
  }

  const domainsInUse = new Set(addresses.map((mailbox) => mailbox.domain)).size

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Addresses"
        title="Your disposable mailboxes"
        description="Every alias you have created or tracked. Open one to read its mail, or copy it to share."
        actions={
          <>
            <Button variant="outline" onClick={() => setTrackOpen(true)}>
              <BookmarkPlus />
              Track existing
            </Button>
            <Button onClick={open}>
              <Sparkles />
              New address
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
        <StatCard label="Mailboxes" value={addresses.length} icon={AtSign} hint="Across all domains" />
        <StatCard label="Saved" value={savedAddresses.length} icon={Bookmark} accent="violet" hint="Bookmarked locally" />
        <StatCard label="Messages" value={totalMessages} icon={Inbox} accent="blue" hint="Stored in D1" />
        <StatCard label="Domains" value={domainsInUse || domains.length} icon={Mail} accent="amber" hint="In use" />
      </div>

      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative w-full sm:max-w-xs">
          <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Filter addresses…"
            className="h-9 bg-card/60 pl-9"
            aria-label="Filter addresses"
          />
        </div>
        <p className="text-[11px] text-muted-foreground">
          {filtered.length} of {addresses.length} shown
        </p>
      </div>

      {filtered.length ? (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {filtered.map((mailbox, index) => {
            const active = mailbox.address === activeAddress
            const saved = isAddressSaved(mailbox.address)
            return (
              <motion.article
                key={mailbox.address}
                initial={prefersReducedMotion ? false : { opacity: 0, y: 14 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{
                  duration: 0.38,
                  delay: Math.min(index, 8) * 0.04,
                  ease: [0.22, 1, 0.36, 1],
                }}
                className={cn(
                  "surface-card group relative overflow-hidden rounded-2xl p-4 transition-shadow hover:shadow-lg hover:shadow-black/5",
                  active && "ring-1 ring-primary/25"
                )}
              >
                <div className="pointer-events-none absolute -top-12 -right-8 size-28 rounded-full bg-primary/8 blur-2xl transition-opacity group-hover:opacity-100" />

                <div className="relative flex items-start gap-3">
                  <div className="relative grid size-11 shrink-0 place-items-center rounded-2xl brand-gradient text-sm font-semibold text-white shadow-md shadow-primary/20">
                    {getInitials(mailbox.localPart)}
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-[13px] font-medium" title={mailbox.address}>
                      {mailbox.localPart}
                      <span className="text-muted-foreground">@{mailbox.domain}</span>
                    </p>
                    <div className="mt-1 flex flex-wrap items-center gap-1.5">
                      {active && (
                        <Badge variant="secondary" className="bg-primary/10 text-primary">
                          Viewing
                        </Badge>
                      )}
                      {saved ? (
                        <Badge variant="outline" className="gap-1 text-[10px]">
                          <Bookmark className="size-2.5" />
                          Saved
                        </Badge>
                      ) : (
                        <Badge variant="ghost" className="text-[10px]">
                          Discovered
                        </Badge>
                      )}
                    </div>
                  </div>

                  <DropdownMenu>
                    <DropdownMenuTrigger
                      render={
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          aria-label={`Actions for ${mailbox.address}`}
                        />
                      }
                    >
                      <MoreHorizontal />
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem onClick={() => openMailbox(mailbox)}>
                        <Inbox />
                        Open inbox
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => copyAddress(mailbox.address)}>
                        <Copy />
                        Copy address
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      {saved ? (
                        <DropdownMenuItem
                          variant="destructive"
                          onClick={() => {
                            removeSavedAddress(mailbox.address)
                            toast.success("Removed bookmark", { description: mailbox.address })
                          }}
                        >
                          <Trash2 />
                          Remove bookmark
                        </DropdownMenuItem>
                      ) : (
                        <DropdownMenuItem onClick={() => addSavedAddress(mailbox.address)}>
                          <BookmarkPlus />
                          Save bookmark
                        </DropdownMenuItem>
                      )}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>

                <div className="relative mt-4 grid grid-cols-2 gap-2 text-[11px]">
                  <div className="rounded-xl bg-muted/45 px-2.5 py-2">
                    <p className="text-muted-foreground">Messages</p>
                    <p className="mt-0.5 text-sm font-semibold tabular-nums">{mailbox.total}</p>
                  </div>
                  <div className="rounded-xl bg-muted/45 px-2.5 py-2">
                    <p className="text-muted-foreground">Latest</p>
                    <p className="mt-0.5 truncate text-[11px] font-medium">
                      {mailbox.latestAt ? formatRelativeTime(mailbox.latestAt) : "No mail yet"}
                    </p>
                  </div>
                </div>

                <div className="relative mt-3 flex gap-2">
                  <Button
                    size="sm"
                    className="flex-1"
                    onClick={() => openMailbox(mailbox)}
                  >
                    <Inbox />
                    Open inbox
                  </Button>
                  <Button
                    variant="outline"
                    size="icon-sm"
                    className="size-8"
                    onClick={() => copyAddress(mailbox.address)}
                    aria-label={`Copy ${mailbox.address}`}
                  >
                    <Copy />
                  </Button>
                </div>
              </motion.article>
            )
          })}

          <motion.button
            type="button"
            onClick={open}
            initial={prefersReducedMotion ? false : { opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.38, delay: Math.min(filtered.length, 8) * 0.04 }}
            className="flex min-h-44 flex-col items-center justify-center gap-2 rounded-2xl border border-dashed border-border/80 bg-card/30 p-4 text-muted-foreground transition-colors hover:border-primary/30 hover:bg-primary/5 hover:text-primary"
          >
            <span className="grid size-10 place-items-center rounded-xl border border-dashed border-current/30">
              <Plus className="size-5" />
            </span>
            <span className="text-xs font-medium">Create another address</span>
          </motion.button>
        </div>
      ) : search ? (
        <EmptyState
          icon={Search}
          title="No addresses match"
          description="Try a different name or domain."
          action={
            <Button variant="outline" size="sm" onClick={() => setSearch("")}>
              Clear filter
            </Button>
          }
        />
      ) : (
        <EmptyState
          icon={AtSign}
          title="No addresses yet"
          description="Create an alias to start receiving mail, or track one you already use."
          action={
            <div className="flex gap-2">
              <Button size="sm" onClick={open}>
                <Sparkles />
                Create address
              </Button>
              <Button variant="outline" size="sm" onClick={() => setTrackOpen(true)}>
                <BookmarkPlus />
                Track existing
              </Button>
            </div>
          }
        />
      )}

      <Dialog open={trackOpen} onOpenChange={setTrackOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Track an existing address</DialogTitle>
            <DialogDescription>
              Add an address to your local bookmarks. This does not create a routing rule.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleTrack} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="track-address">Email address</Label>
              <Input
                id="track-address"
                value={trackValue}
                onChange={(event) => {
                  setTrackValue(event.target.value)
                  setTrackError("")
                }}
                placeholder="hello@example.com"
                className="font-mono text-[13px]"
                autoFocus
              />
              {trackError && (
                <p role="alert" className="text-xs font-medium text-destructive">
                  {trackError}
                </p>
              )}
            </div>
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => setTrackOpen(false)}>
                Cancel
              </Button>
              <Button type="submit">
                <BookmarkPlus />
                Track address
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}

