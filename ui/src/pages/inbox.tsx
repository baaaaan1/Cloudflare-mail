import * as React from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import {
  ArrowLeft,
  ArrowRight,
  ChevronLeft,
  ChevronRight,
  Copy,
  Inbox,
  RefreshCw,
  Search,
  SlidersHorizontal,
  Sparkles,
} from "lucide-react"
import { toast } from "sonner"

import { EmailReader } from "@/components/email-reader"
import { EmptyState } from "@/components/empty-state"
import { ErrorState } from "@/components/error-state"
import { MessageListItem } from "@/components/message-list-item"
import { PageHeader } from "@/components/page-header"
import { ListSkeleton } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetTitle,
} from "@/components/ui/sheet"
import { useIsDesktop } from "@/hooks/use-media-query"
import { useWorkspace } from "@/hooks/use-workspace"
import { apiClient } from "@/lib/api"
import { PAGE_SIZE } from "@/lib/constants"
import { copyText, formatCompactNumber, localPartOf, pluralize } from "@/lib/format"
import { queryKeys, STORAGE_KEYS } from "@/lib/query-keys"
import { navigate, useRoute } from "@/lib/router"
import type { EmailSummaryItem } from "@/lib/types"
import { cn } from "cn"

type SortValue =
  | "newest"
  | "oldest"
  | "sender-az"
  | "sender-za"
  | "recipient-az"
  | "recipient-za"

const SORT_OPTIONS: { value: SortValue; label: string }[] = [
  { value: "newest", label: "Newest first" },
  { value: "oldest", label: "Oldest first" },
  { value: "sender-az", label: "Sender A–Z" },
  { value: "sender-za", label: "Sender Z–A" },
  { value: "recipient-az", label: "Recipient A–Z" },
  { value: "recipient-za", label: "Recipient Z–A" },
]

function readReadIds() {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.readMessages)
    const parsed = raw ? (JSON.parse(raw) as unknown) : []
    if (!Array.isArray(parsed)) return new Set<string>()
    return new Set(parsed.map((value) => String(value)))
  } catch {
    return new Set<string>()
  }
}

function persistReadIds(ids: Set<string>) {
  try {
    localStorage.setItem(
      STORAGE_KEYS.readMessages,
      JSON.stringify(Array.from(ids).slice(-800))
    )
  } catch {
    // Local persistence is a convenience; ignore quota errors.
  }
}

export function InboxPage() {
  const { activeAddress, addresses, summary, setActiveAddress } = useWorkspace()
  const { messageId } = useRoute()
  const isDesktop = useIsDesktop()
  const queryClient = useQueryClient()

  const [page, setPage] = React.useState(0)
  const [search, setSearch] = React.useState("")
  const [sort, setSort] = React.useState<SortValue>("newest")
  const [readIds, setReadIds] = React.useState<Set<string>>(readReadIds)
  const initializedReadRef = React.useRef(false)
  const searchRef = React.useRef<HTMLInputElement>(null)

  const scope = activeAddress || "all"
  const summaryTotal = activeAddress
    ? Number(summary.find((row) => row.recipient?.toLowerCase() === activeAddress)?.total) || 0
    : summary.reduce((total, row) => total + (Number(row.total) || 0), 0)

  const inboxQuery = useQuery({
    queryKey: queryKeys.inbox(scope, page),
    queryFn: () =>
      apiClient.inbox({
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
        recipients: activeAddress || undefined,
      }),
    staleTime: 30_000,
    retry: 1,
  })

  const emails = React.useMemo(() => inboxQuery.data ?? [], [inboxQuery.data])
  const loading = inboxQuery.isLoading

  React.useEffect(() => {
    setPage(0)
    initializedReadRef.current = false
  }, [activeAddress])

  React.useEffect(() => {
    if (initializedReadRef.current || !emails.length) return
    initializedReadRef.current = true
    if (localStorage.getItem(STORAGE_KEYS.readMessages)) return
    setReadIds(() => {
      const next = new Set(emails.map((email) => String(email.id)))
      persistReadIds(next)
      return next
    })
  }, [emails])

  React.useEffect(() => {
    if (!messageId) return
    setReadIds((current) => {
      const key = String(messageId)
      if (current.has(key)) return current
      const next = new Set(current)
      next.add(key)
      persistReadIds(next)
      return next
    })
  }, [messageId])

  const filtered = React.useMemo(() => {
    const term = search.trim().toLowerCase()
    if (!term) return emails
    return emails.filter((email) =>
      `${email.subject || ""} ${email.sender || ""} ${email.recipient || ""}`
        .toLowerCase()
        .includes(term)
    )
  }, [emails, search])

  const sorted = React.useMemo(() => {
    const list = [...filtered]
    list.sort((left, right) => {
      const leftTime = new Date(left.created_at || 0).getTime()
      const rightTime = new Date(right.created_at || 0).getTime()
      if (sort === "oldest") return leftTime - rightTime
      if (sort === "sender-az") return (left.sender || "").localeCompare(right.sender || "")
      if (sort === "sender-za") return (right.sender || "").localeCompare(left.sender || "")
      if (sort === "recipient-az")
        return (left.recipient || "").localeCompare(right.recipient || "")
      if (sort === "recipient-za")
        return (right.recipient || "").localeCompare(left.recipient || "")
      return rightTime - leftTime
    })
    return list
  }, [filtered, sort])

  const hasNext = emails.length === PAGE_SIZE
  const selectedEmail = messageId
    ? emails.find((email) => email.id === messageId) ?? null
    : null

  const openMessage = (email: EmailSummaryItem) => {
    navigate(`/inbox/${email.id}`)
  }

  const closeMessage = () => navigate("/inbox", { replace: true })

  const moveSelection = React.useCallback(
    (delta: number) => {
      if (!sorted.length) return
      const currentIndex = sorted.findIndex((email) => email.id === messageId)
      const nextIndex =
        currentIndex === -1
          ? delta > 0
            ? 0
            : sorted.length - 1
          : Math.min(Math.max(currentIndex + delta, 0), sorted.length - 1)
      const next = sorted[nextIndex]
      if (next) navigate(`/inbox/${next.id}`)
    },
    [messageId, sorted]
  )

  React.useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target
      if (
        target instanceof HTMLElement &&
        target.closest("input, textarea, select, [contenteditable='true']")
      ) {
        if (event.key === "Escape") {
          searchRef.current?.blur()
          if (messageId) closeMessage()
        }
        return
      }
      if (event.metaKey || event.ctrlKey || event.altKey) return

      if (event.key === "/") {
        event.preventDefault()
        searchRef.current?.focus()
      } else if (event.key.toLowerCase() === "j") {
        event.preventDefault()
        moveSelection(1)
      } else if (event.key.toLowerCase() === "k") {
        event.preventDefault()
        moveSelection(-1)
      } else if (event.key.toLowerCase() === "r") {
        event.preventDefault()
        void inboxQuery.refetch()
      } else if (event.key === "Escape" && messageId) {
        closeMessage()
      }
    }

    window.addEventListener("keydown", onKeyDown)
    return () => window.removeEventListener("keydown", onKeyDown)
  }, [inboxQuery, messageId, moveSelection])

  const copyActive = () => {
    if (!activeAddress) return
    void copyText(activeAddress)
      .then(() => toast.success("Address copied", { description: activeAddress }))
      .catch(() => toast.error("Could not copy address"))
  }

  const refreshInbox = async () => {
    await Promise.all([
      inboxQuery.refetch(),
      queryClient.invalidateQueries({ queryKey: queryKeys.inboxSummary }),
    ])
    toast.success("Inbox refreshed")
  }

  const reader = (
    <EmailReader
      messageId={messageId}
      onClose={closeMessage}
      onDeleted={() => {
        void queryClient.invalidateQueries({ queryKey: ["inbox"] })
      }}
    />
  )

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Inbox"
        title={activeAddress ? localPartOf(activeAddress) : "All messages"}
        description={
          activeAddress
            ? `${activeAddress} · ${pluralize(summaryTotal, "message")} received`
            : `Every address in one place · ${pluralize(summaryTotal, "message")} received`
        }
        actions={
          <>
            {activeAddress && (
              <Button variant="outline" onClick={copyActive}>
                <Copy />
                Copy address
              </Button>
            )}
            <Button variant="outline" onClick={refreshInbox} disabled={inboxQuery.isFetching}>
              <RefreshCw className={cn(inboxQuery.isFetching && "animate-spin")} />
              Refresh
            </Button>
            <Button onClick={() => navigate("/addresses")} className="hidden sm:inline-flex">
              <Sparkles />
              Manage addresses
            </Button>
          </>
        }
      />

      <div className="surface-card grid overflow-hidden rounded-2xl lg:h-[calc(100svh-15rem)] lg:grid-cols-[minmax(320px,420px)_1fr]">
        <div className="flex min-h-0 flex-col border-border/60 lg:border-r">
          <div className="border-b border-border/60 p-3">
            <div className="flex flex-col gap-2">
              <div className="relative">
                <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  ref={searchRef}
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search this page…"
                  className="h-9 bg-background/60 pr-10 pl-9"
                  aria-label="Search messages"
                />
                <kbd className="pointer-events-none absolute top-1/2 right-2.5 -translate-y-1/2 rounded border border-border bg-muted/60 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                  /
                </kbd>
              </div>

              <div className="flex items-center gap-2">
                <Select
                  value={activeAddress || "__all__"}
                  onValueChange={(value) =>
                    setActiveAddress(String(value) === "__all__" ? "" : String(value))
                  }
                >
                  <SelectTrigger className="h-9 min-w-0 flex-1" aria-label="Filter by mailbox">
                    <SelectValue>
                      {(value) =>
                        value === "__all__"
                          ? "All mailboxes"
                          : addresses.find((address) => address.address === value)?.address ??
                            "All mailboxes"
                      }
                    </SelectValue>
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__all__">All mailboxes</SelectItem>
                    {addresses.map((address) => (
                      <SelectItem key={address.address} value={address.address}>
                        {address.address}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>

                <Select value={sort} onValueChange={(value) => setSort(value as SortValue)}>
                  <SelectTrigger className="h-9 w-10 shrink-0 px-0 sm:w-36 sm:px-3" aria-label="Sort messages">
                    <SlidersHorizontal className="sm:hidden" />
                    <SelectValue>
                      {(value) =>
                        SORT_OPTIONS.find((option) => option.value === value)?.label ?? "Sort"
                      }
                    </SelectValue>
                  </SelectTrigger>
                  <SelectContent align="end">
                    {SORT_OPTIONS.map((option) => (
                      <SelectItem key={option.value} value={option.value}>
                        {option.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto p-2 scrollbar-thin max-lg:max-h-[58svh]">
            {loading ? (
              <ListSkeleton rows={6} />
            ) : inboxQuery.error ? (
              <div className="p-2">
                <ErrorState
                  title="Inbox unavailable"
                  message={inboxQuery.error.message}
                  onRetry={() => void inboxQuery.refetch()}
                />
              </div>
            ) : sorted.length ? (
              <div className="space-y-0.5">
                {sorted.map((email, index) => (
                  <MessageListItem
                    key={email.id}
                    email={email}
                    index={index}
                    active={email.id === messageId}
                    read={readIds.has(String(email.id))}
                    onClick={() => openMessage(email)}
                  />
                ))}
              </div>
            ) : search ? (
              <EmptyState
                icon={Search}
                title="No matches on this page"
                description="Try a different keyword, or clear the search to see everything."
                action={
                  <Button variant="outline" size="sm" onClick={() => setSearch("")}>
                    Clear search
                  </Button>
                }
              />
            ) : (
              <EmptyState
                icon={Inbox}
                title={activeAddress ? "This mailbox is quiet" : "Your inbox is quiet"}
                description={
                  activeAddress
                    ? `Nothing has arrived at ${activeAddress} yet. Send a test email to see it here.`
                    : "Create an address, then send a test email to watch it land here."
                }
                action={
                  activeAddress ? (
                    <Button variant="outline" size="sm" onClick={copyActive}>
                      <Copy />
                      Copy address
                    </Button>
                  ) : (
                    <Button size="sm" onClick={() => navigate("/addresses")}>
                      <Sparkles />
                      Create address
                    </Button>
                  )
                }
              />
            )}
          </div>

          <div className="flex items-center justify-between gap-3 border-t border-border/60 px-3 py-2.5">
            <div className="min-w-0 text-[10px] text-muted-foreground">
              {loading
                ? "Loading…"
                : sorted.length
                  ? `${formatCompactNumber(sorted.length)} on this page`
                  : "No messages"}
              <span className="mx-1.5 text-border">·</span>
              Page {page + 1}
            </div>
            <div className="flex items-center gap-1">
              <Button
                variant="outline"
                size="icon-sm"
                onClick={() => setPage((current) => Math.max(current - 1, 0))}
                disabled={page === 0 || loading}
                aria-label="Previous page"
              >
                <ChevronLeft />
              </Button>
              <Button
                variant="outline"
                size="icon-sm"
                onClick={() => setPage((current) => current + 1)}
                disabled={!hasNext || loading}
                aria-label="Next page"
              >
                <ChevronRight />
              </Button>
            </div>
          </div>
        </div>

        <div className="hidden min-h-0 lg:block">{reader}</div>
      </div>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-1 text-[10px] text-muted-foreground">
        <span className="inline-flex items-center gap-1">
          <kbd className="rounded border border-border bg-muted/50 px-1.5 py-0.5 font-mono">J</kbd>
          <kbd className="rounded border border-border bg-muted/50 px-1.5 py-0.5 font-mono">K</kbd>
          next / previous
        </span>
        <span className="inline-flex items-center gap-1">
          <kbd className="rounded border border-border bg-muted/50 px-1.5 py-0.5 font-mono">/</kbd>
          search
        </span>
        <span className="inline-flex items-center gap-1">
          <kbd className="rounded border border-border bg-muted/50 px-1.5 py-0.5 font-mono">R</kbd>
          refresh
        </span>
        <span className="ml-auto hidden items-center gap-1 sm:inline-flex">
          {selectedEmail ? (
            <>
              <ArrowLeft className="size-3" />
              Selected #{selectedEmail.id}
            </>
          ) : (
            <>
              Open a message
              <ArrowRight className="size-3" />
            </>
          )}
        </span>
      </div>

      {!isDesktop && (
        <Sheet
          open={messageId !== null}
          onOpenChange={(open) => {
            if (!open) closeMessage()
          }}
        >
          <SheetContent
            side="right"
            showCloseButton={false}
            className="w-full max-w-none gap-0 p-0 sm:max-w-lg"
          >
            <SheetTitle className="sr-only">Message</SheetTitle>
            <SheetDescription className="sr-only">
              Read the selected email message.
            </SheetDescription>
            {reader}
          </SheetContent>
        </Sheet>
      )}
    </div>
  )
}

