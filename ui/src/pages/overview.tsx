import * as React from "react"
import { useQuery } from "@tanstack/react-query"
import {
  ArrowRight,
  ArrowUpRight,
  AtSign,
  Check,
  CircleAlert,
  Copy,
  Database,
  Inbox,
  KeyRound,
  Loader2,
  Mail,
  RefreshCw,
  Send,
  Settings2,
  Sparkles,
  Wand2,
} from "lucide-react"
import { motion, useReducedMotion } from "motion/react"
import { toast } from "sonner"

import { useCreateAddressDialog } from "@/components/create-address-context"
import { EmptyState } from "@/components/empty-state"
import { ErrorState } from "@/components/error-state"
import { MessageListItem } from "@/components/message-list-item"
import { PageHeader } from "@/components/page-header"
import { StatCard } from "@/components/stat-card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useCreateAddress } from "@/hooks/use-create-address"
import { useWorkspace } from "@/hooks/use-workspace"
import { apiClient } from "@/lib/api"
import { createRandomLocalPart, validateLocalPart } from "@/lib/random"
import { copyText, formatRelativeTime, getInitials, greeting, localPartOf, pluralize } from "@/lib/format"
import { queryKeys } from "@/lib/query-keys"
import { Link, navigate } from "@/lib/router"
import type { NameStyle } from "@/lib/types"
import { cn } from "cn"

export function OverviewPage() {
  const {
    domains,
    domainsError,
    domainsLoading,
    config,
    health,
    healthError,
    addresses,
    activeAddress,
    setActiveAddress,
    totalMessages,
    mailboxCount,
    savedAddresses,
    latestAddress,
    refreshWorkspace,
  } = useWorkspace()
  const { open } = useCreateAddressDialog()
  const prefersReducedMotion = useReducedMotion()

  const [name, setName] = React.useState("")
  const [domainId, setDomainId] = React.useState("")
  const [error, setError] = React.useState("")
  const [refreshing, setRefreshing] = React.useState(false)

  React.useEffect(() => {
    if (!domainId && domains.length) setDomainId(domains[0].id)
  }, [domainId, domains])

  const { createAddress, isCreating } = useCreateAddress({
    onCreated: () => {
      setName("")
      setError("")
    },
  })

  const destinationsQuery = useQuery({
    queryKey: queryKeys.destinations,
    queryFn: apiClient.destinations,
    staleTime: 5 * 60_000,
    retry: 1,
  })

  const recentQuery = useQuery({
    queryKey: queryKeys.inbox(`recent-${activeAddress || "all"}`, 0),
    queryFn: () =>
      apiClient.inbox({
        limit: 5,
        offset: 0,
        recipients: activeAddress || undefined,
      }),
    staleTime: 30_000,
    retry: 1,
  })

  const selectedDomain = domains.find((domain) => domain.id === domainId) ?? null
  const preview = `${name.trim() || "hello"}@${selectedDomain?.name || "your-domain.com"}`

  const handleQuickCreate = async (event: React.FormEvent) => {
    event.preventDefault()
    const validationError = validateLocalPart(name)
    if (validationError) {
      setError(validationError)
      return
    }
    if (!selectedDomain) {
      setError("Select a domain, or connect Cloudflare in settings.")
      return
    }
    setError("")
    try {
      await createAddress({ localPart: name, domain: selectedDomain, style: "us" as NameStyle })
    } catch (creationError) {
      setError(creationError instanceof Error ? creationError.message : "Could not create address")
    }
  }

  const fillRandom = () => {
    setName(createRandomLocalPart("us"))
    setError("")
    if (domains.length > 1) {
      const domain = domains[Math.floor(Math.random() * domains.length)]
      if (domain) setDomainId(domain.id)
    }
  }

  const handleRefresh = async () => {
    setRefreshing(true)
    try {
      await refreshWorkspace()
      toast.success("Workspace refreshed")
    } finally {
      setRefreshing(false)
    }
  }

  const copyAddress = (address: string) => {
    void copyText(address)
      .then(() => toast.success("Address copied", { description: address }))
      .catch(() => toast.error("Could not copy address"))
  }

  const recentMessages = recentQuery.data ?? []
  const healthOk = !healthError && health?.ok !== false
  const needsSetup = Boolean(config && !config.has_token)

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Dashboard"
        title={`${greeting()}. Your inbox is ready.`}
        description="Create disposable addresses, watch mail arrive, and tune routing — all from one quiet workspace."
        actions={
          <>
            <Button
              variant="outline"
              onClick={handleRefresh}
              disabled={refreshing}
              className="hidden sm:inline-flex"
            >
              <RefreshCw className={cn(refreshing && "animate-spin")} />
              Refresh
            </Button>
            <Button onClick={open}>
              <Sparkles />
              New address
            </Button>
          </>
        }
      />

      {needsSetup && (
        <motion.div
          initial={prefersReducedMotion ? false : { opacity: 0, y: -6 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex flex-col gap-3 rounded-2xl border border-amber-500/25 bg-amber-500/8 p-4 sm:flex-row sm:items-center"
        >
          <div className="flex flex-1 items-start gap-3">
            <div className="grid size-9 shrink-0 place-items-center rounded-xl bg-amber-500/15 text-amber-600 dark:text-amber-400">
              <CircleAlert className="size-4" />
            </div>
            <div>
              <p className="text-sm font-medium">Connect your Cloudflare account</p>
              <p className="mt-0.5 text-xs text-muted-foreground">
                Add an API token and account ID to load domains, routes, and destinations.
              </p>
            </div>
          </div>
          <Button variant="outline" size="sm" onClick={() => navigate("/settings")}>
            <Settings2 />
            Open settings
          </Button>
        </motion.div>
      )}

      <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
        <StatCard
          label="Mailboxes"
          value={mailboxCount}
          hint={savedAddresses.length ? `${savedAddresses.length} saved locally` : "Create your first one"}
          icon={AtSign}
          index={0}
        />
        <StatCard
          label="Messages"
          value={totalMessages}
          hint={activeAddress ? `Viewing ${localPartOf(activeAddress)}` : "Across all mailboxes"}
          icon={Inbox}
          accent="blue"
          index={1}
        />
        <StatCard
          label="Domains"
          value={domains.length}
          hint={domainsError ? "Cloudflare unavailable" : "Connected zones"}
          icon={Mail}
          accent="violet"
          index={2}
        />
        <StatCard
          label="Destinations"
          value={destinationsQuery.data?.length ?? 0}
          hint={destinationsQuery.error ? "Could not load" : "Verified forwarding targets"}
          icon={Send}
          accent="amber"
          index={3}
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.35fr_0.65fr]">
        <div className="space-y-4">
          <motion.section
            initial={prefersReducedMotion ? false : { opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.08, ease: [0.22, 1, 0.36, 1] }}
            className="surface-card relative overflow-hidden rounded-3xl p-5 sm:p-7"
          >
            <div className="pointer-events-none absolute -top-24 -right-16 size-64 rounded-full bg-primary/15 blur-3xl" />
            <div className="pointer-events-none absolute -bottom-24 -left-10 size-48 rounded-full bg-chart-2/10 blur-3xl" />

            <div className="relative grid gap-7 lg:grid-cols-[1.25fr_0.75fr] lg:items-center">
              <div>
                <Badge variant="secondary" className="mb-3 gap-1.5 border border-primary/15 bg-primary/8 text-primary">
                  <Sparkles className="size-3" />
                  Instant aliases
                </Badge>
                <h2 className="max-w-md text-xl font-semibold tracking-tight text-balance sm:text-2xl">
                  A fresh address, <span className="text-gradient">without the signup.</span>
                </h2>
                <p className="mt-2 max-w-md text-sm leading-relaxed text-muted-foreground">
                  Pick a name and a domain. We&apos;ll create the routing rule and point it to your
                  inbox worker instantly.
                </p>

                <form onSubmit={handleQuickCreate} className="mt-5 space-y-3">
                  <div className="flex flex-col gap-2 sm:flex-row">
                    <div className="relative min-w-0 flex-1">
                      <AtSign className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
                      <Input
                        value={name}
                        onChange={(event) => {
                          setName(event.target.value)
                          setError("")
                        }}
                        placeholder="name"
                        className="h-10 bg-background/70 pl-9 font-mono text-[13px]"
                        aria-label="Address name"
                        autoComplete="off"
                      />
                    </div>
                    <Select
                      value={domainId || undefined}
                      onValueChange={(value) => setDomainId(String(value || ""))}
                      disabled={domainsLoading || !domains.length}
                    >
                      <SelectTrigger className="h-10 w-full bg-background/70 sm:w-48" aria-label="Domain">
                        <SelectValue>
                          {(value) =>
                            domains.find((domain) => domain.id === value)?.name ??
                            (domainsLoading ? "Loading…" : "Domain")
                          }
                        </SelectValue>
                      </SelectTrigger>
                      <SelectContent>
                        {domains.map((domain) => (
                          <SelectItem key={domain.id} value={domain.id}>
                            {domain.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Button
                      type="button"
                      variant="outline"
                      size="icon"
                      className="hidden h-10 shrink-0 sm:inline-flex"
                      onClick={fillRandom}
                      aria-label="Random name"
                      title="Random name"
                    >
                      <Wand2 />
                    </Button>
                  </div>
                  <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                    <Button type="submit" disabled={isCreating || !domains.length} className="h-10 sm:min-w-36">
                      {isCreating ? <Loader2 className="animate-spin" /> : <Check />}
                      {isCreating ? "Creating…" : "Create address"}
                    </Button>
                    <span className="truncate font-mono text-[11px] text-muted-foreground">
                      {preview}
                    </span>
                  </div>
                  {error && (
                    <p role="alert" className="text-xs font-medium text-destructive">
                      {error}
                    </p>
                  )}
                  {domainsError && (
                    <p className="text-xs text-amber-600 dark:text-amber-400">
                      Domains unavailable.{" "}
                      <Link to="/settings" className="underline underline-offset-2">
                        Check credentials
                      </Link>
                      .
                    </p>
                  )}
                </form>
              </div>

              <div className="relative hidden min-h-44 lg:block" aria-hidden="true">
                {[2, 1, 0].map((offset) => (
                  <motion.div
                    key={offset}
                    initial={prefersReducedMotion ? false : { opacity: 0, y: 24, rotate: -6 + offset * 4 }}
                    animate={{ opacity: 1, y: 0, rotate: -6 + offset * 4 }}
                    transition={{
                      duration: 0.6,
                      delay: 0.15 + offset * 0.08,
                      ease: [0.22, 1, 0.36, 1],
                    }}
                    className={cn(
                      "absolute inset-x-4 rounded-2xl border border-border/70 bg-card/90 p-3.5 shadow-xl shadow-black/5 backdrop-blur",
                      offset === 0 && "ring-1 ring-primary/15"
                    )}
                    style={{
                      top: `${offset * 26}px`,
                      zIndex: 3 - offset,
                      marginLeft: `${offset * 10}px`,
                      marginRight: `${offset * 10}px`,
                    }}
                  >
                    <div className="flex items-center gap-2">
                      <span className="grid size-6 place-items-center rounded-lg bg-primary/10 text-primary">
                        <Mail className="size-3" />
                      </span>
                      <span className="text-[10px] font-medium text-muted-foreground">
                        {offset === 0 ? "Just now" : `${offset * 3} min ago`}
                      </span>
                      <span className="ml-auto size-1.5 rounded-full bg-primary/50" />
                    </div>
                    <p className="mt-2 truncate text-[11px] font-medium">
                      {offset === 0 ? "Your new address is live" : "Welcome to Cloudflare Mail"}
                    </p>
                    <p className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground">
                      {offset === 0 ? preview : `hello@${selectedDomain?.name || "your-domain.com"}`}
                    </p>
                  </motion.div>
                ))}
              </div>
            </div>
          </motion.section>

          <motion.section
            initial={prefersReducedMotion ? false : { opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.14, ease: [0.22, 1, 0.36, 1] }}
            className="surface-card overflow-hidden rounded-2xl"
          >
            <div className="flex items-center justify-between gap-3 border-b border-border/60 px-4 py-3.5">
              <div>
                <h2 className="text-sm font-semibold">Recent messages</h2>
                <p className="mt-0.5 text-[11px] text-muted-foreground">
                  {activeAddress ? `Latest mail for ${activeAddress}` : "Newest across all mailboxes"}
                </p>
              </div>
              <Button variant="ghost" size="sm" render={<Link to="/inbox" />}>
                View inbox
                <ArrowRight />
              </Button>
            </div>

            {recentQuery.isLoading ? (
              <div className="space-y-2 p-2">
                {Array.from({ length: 4 }).map((_, index) => (
                  <div key={index} className="flex items-center gap-3 p-3">
                    <div className="size-9 animate-pulse rounded-full bg-muted" />
                    <div className="flex-1 space-y-2">
                      <div className="h-3 w-32 animate-pulse rounded bg-muted" />
                      <div className="h-3 w-3/4 animate-pulse rounded bg-muted" />
                    </div>
                  </div>
                ))}
              </div>
            ) : recentQuery.error ? (
              <div className="p-3">
                <ErrorState
                  title="Inbox unavailable"
                  message={recentQuery.error.message}
                  onRetry={() => void recentQuery.refetch()}
                />
              </div>
            ) : recentMessages.length ? (
              <div className="space-y-0.5 p-2">
                {recentMessages.map((email, index) => (
                  <MessageListItem
                    key={email.id}
                    email={email}
                    index={index}
                    compact
                    onClick={() => navigate(`/inbox/${email.id}`)}
                  />
                ))}
              </div>
            ) : (
              <EmptyState
                icon={Inbox}
                title="No messages yet"
                description="Send a test email to one of your addresses and it will appear here."
                action={
                  activeAddress ? (
                    <Button variant="outline" size="sm" onClick={() => copyAddress(activeAddress)}>
                      <Copy />
                      Copy address
                    </Button>
                  ) : undefined
                }
              />
            )}
          </motion.section>
        </div>

        <div className="space-y-4">
          <motion.section
            initial={prefersReducedMotion ? false : { opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1, ease: [0.22, 1, 0.36, 1] }}
            className="surface-card rounded-2xl p-4"
          >
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold">Your mailboxes</h2>
              <Button variant="ghost" size="icon-sm" onClick={open} aria-label="Create address">
                <Sparkles />
              </Button>
            </div>

            <div className="mt-3 space-y-1">
              {addresses.slice(0, 5).map((mailbox) => {
                const active = mailbox.address === activeAddress
                return (
                  <div
                    key={mailbox.address}
                    className={cn(
                      "group flex items-center gap-2.5 rounded-xl px-2 py-2 transition-colors",
                      active ? "bg-primary/8" : "hover:bg-muted/60"
                    )}
                  >
                    <button
                      type="button"
                      onClick={() => {
                        setActiveAddress(mailbox.address)
                        navigate("/inbox")
                      }}
                      className="flex min-w-0 flex-1 items-center gap-2.5 text-left"
                    >
                      <span
                        className={cn(
                          "grid size-8 shrink-0 place-items-center rounded-full text-[10px] font-semibold",
                          active
                            ? "bg-primary text-primary-foreground"
                            : "bg-muted text-muted-foreground"
                        )}
                      >
                        {getInitials(mailbox.localPart)}
                      </span>
                      <span className="min-w-0">
                        <span className="block truncate text-[12px] font-medium">
                          {localPartOf(mailbox.address)}
                        </span>
                        <span className="block truncate text-[10px] text-muted-foreground">
                          {pluralize(mailbox.total, "message")}
                          {mailbox.latestAt ? ` · ${formatRelativeTime(mailbox.latestAt)}` : ""}
                        </span>
                      </span>
                    </button>
                    <button
                      type="button"
                      onClick={() => copyAddress(mailbox.address)}
                      className="opacity-0 transition-opacity group-hover:opacity-100 focus-visible:opacity-100"
                      aria-label={`Copy ${mailbox.address}`}
                    >
                      <Copy className="size-3.5 text-muted-foreground" />
                    </button>
                  </div>
                )
              })}

              {!addresses.length && (
                <div className="rounded-xl border border-dashed border-border/70 px-3 py-6 text-center">
                  <AtSign className="mx-auto size-5 text-muted-foreground" />
                  <p className="mt-2 text-xs font-medium">No mailboxes yet</p>
                  <p className="mt-1 text-[11px] text-muted-foreground">
                    Your first alias is one click away.
                  </p>
                  <Button size="sm" variant="outline" className="mt-3" onClick={open}>
                    <Sparkles />
                    Create address
                  </Button>
                </div>
              )}
            </div>

            {addresses.length > 5 && (
              <Button
                variant="ghost"
                size="sm"
                className="mt-2 w-full justify-between"
                onClick={() => navigate("/addresses")}
              >
                View all {addresses.length} mailboxes
                <ArrowRight />
              </Button>
            )}
          </motion.section>

          <motion.section
            initial={prefersReducedMotion ? false : { opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.16, ease: [0.22, 1, 0.36, 1] }}
            className="surface-card rounded-2xl p-4"
          >
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold">Workspace</h2>
              <Badge
                variant="secondary"
                className={cn(
                  "gap-1",
                  healthOk
                    ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                    : "bg-amber-500/10 text-amber-700 dark:text-amber-300"
                )}
              >
                <span
                  className={cn(
                    "size-1.5 rounded-full",
                    healthOk ? "bg-emerald-500" : "bg-amber-500"
                  )}
                />
                {healthOk ? "Healthy" : "Check setup"}
              </Badge>
            </div>

            <div className="mt-3 space-y-2.5">
              <div className="flex items-center gap-3">
                <span className="grid size-7 place-items-center rounded-lg bg-muted text-muted-foreground">
                  <KeyRound className="size-3.5" />
                </span>
                <span className="flex-1 text-[12px]">Cloudflare API</span>
                <Badge variant={config?.has_token ? "secondary" : "destructive"}>
                  {config?.has_token ? "Configured" : "Missing"}
                </Badge>
              </div>
              <div className="flex items-center gap-3">
                <span className="grid size-7 place-items-center rounded-lg bg-muted text-muted-foreground">
                  <Database className="size-3.5" />
                </span>
                <span className="flex-1 text-[12px]">D1 inbox storage</span>
                <Badge variant={config?.d1_database_id ? "secondary" : "destructive"}>
                  {config?.d1_database_id ? "Connected" : "Missing"}
                </Badge>
              </div>
              <div className="flex items-center gap-3">
                <span className="grid size-7 place-items-center rounded-lg bg-muted text-muted-foreground">
                  <Send className="size-3.5" />
                </span>
                <span className="flex-1 text-[12px]">Destinations</span>
                <span className="text-[11px] font-medium tabular-nums">
                  {destinationsQuery.data?.length ?? 0}
                </span>
              </div>
              <div className="flex items-center gap-3">
                <span className="grid size-7 place-items-center rounded-lg bg-muted text-muted-foreground">
                  <Inbox className="size-3.5" />
                </span>
                <span className="flex-1 text-[12px]">Latest address</span>
                <span className="max-w-32 truncate font-mono text-[10px] text-muted-foreground">
                  {latestAddress?.address || "—"}
                </span>
              </div>
            </div>

            <div className="mt-3 flex gap-2">
              <Button
                variant="outline"
                size="sm"
                className="flex-1"
                onClick={() => navigate("/settings")}
              >
                <Settings2 />
                Settings
              </Button>
              <Button
                variant="ghost"
                size="icon-sm"
                onClick={() => navigate("/settings")}
                aria-label="Open diagnostics"
              >
                <ArrowUpRight />
              </Button>
            </div>
          </motion.section>
        </div>
      </div>
    </div>
  )
}
