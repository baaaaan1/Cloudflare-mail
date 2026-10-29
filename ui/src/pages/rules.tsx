import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  ArrowRight,
  Check,
  Copy,
  Cpu,
  Inbox,
  Loader2,
  Mail,
  Plus,
  RefreshCw,
  Route,
  Search,
  Send,
  Settings2,
  Trash2,
  Zap,
} from "lucide-react"
import { motion, useReducedMotion } from "motion/react"
import { toast } from "sonner"

import { EmptyState } from "@/components/empty-state"
import { ErrorState } from "@/components/error-state"
import { PageHeader } from "@/components/page-header"
import { StatCard } from "@/components/stat-card"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { useWorkspace } from "@/hooks/use-workspace"
import { apiClient } from "@/lib/api"
import { copyText } from "@/lib/format"
import { queryKeys } from "@/lib/query-keys"
import { navigate } from "@/lib/router"
import type { Destination, Rule } from "@/lib/types"
import { cn } from "cn"

type FilterValue = "all" | "active" | "paused"

function ruleEmail(rule: Rule) {
  const matcher = rule.matchers?.find((item) => item.value)
  return matcher?.value || rule.name?.replace(/^route:/, "") || "—"
}

function ruleAction(rule: Rule) {
  const action = rule.actions?.[0]
  if (!action) return { type: "unknown", value: "No action" }
  if (action.type === "drop") return { type: "drop", value: "Drop silently" }
  if (action.type === "worker")
    return { type: "worker", value: action.value?.join(", ") || "Worker" }
  return { type: "forward", value: action.value?.join(", ") || "Forward" }
}

function ActionIcon({ type }: { type: string }) {
  if (type === "worker") return <Cpu className="size-4" />
  if (type === "drop") return <Trash2 className="size-4" />
  return <Send className="size-4" />
}

export function RulesPage() {
  const { domains, domainsError, domainsLoading, workers, setActiveAddress } = useWorkspace()
  const queryClient = useQueryClient()
  const prefersReducedMotion = useReducedMotion()

  const [zoneId, setZoneId] = React.useState("")
  const [search, setSearch] = React.useState("")
  const [filter, setFilter] = React.useState<FilterValue>("all")
  const [createOpen, setCreateOpen] = React.useState(false)
  const [deleteTarget, setDeleteTarget] = React.useState<Rule | null>(null)

  React.useEffect(() => {
    if (!zoneId && domains.length) setZoneId(domains[0].id)
  }, [domains, zoneId])

  const selectedDomain = domains.find((domain) => domain.id === zoneId) ?? null

  const rulesQuery = useQuery({
    queryKey: queryKeys.rules(zoneId || null),
    queryFn: () => apiClient.rules(zoneId),
    enabled: Boolean(zoneId),
    staleTime: 30_000,
    retry: 1,
  })

  const destinationsQuery = useQuery({
    queryKey: queryKeys.destinations,
    queryFn: apiClient.destinations,
    staleTime: 5 * 60_000,
    retry: 1,
  })

  const rules = React.useMemo(() => rulesQuery.data ?? [], [rulesQuery.data])
  const enabledCount = rules.filter((rule) => rule.enabled).length
  const workerCount = rules.filter((rule) => ruleAction(rule).type === "worker").length
  const forwardCount = rules.filter((rule) => ruleAction(rule).type === "forward").length

  const filtered = React.useMemo(() => {
    const term = search.trim().toLowerCase()
    return rules.filter((rule) => {
      if (filter === "active" && !rule.enabled) return false
      if (filter === "paused" && rule.enabled) return false
      if (!term) return true
      const action = ruleAction(rule)
      return `${ruleEmail(rule)} ${rule.name || ""} ${action.value}`.toLowerCase().includes(term)
    })
  }, [filter, rules, search])

  const toggleMutation = useMutation({
    mutationFn: ({ rule, enabled }: { rule: Rule; enabled: boolean }) =>
      apiClient.updateRule(rule.id, { enabled, zoneId }),
    onMutate: async ({ rule, enabled }) => {
      const key = queryKeys.rules(zoneId)
      await queryClient.cancelQueries({ queryKey: key })
      const previous = queryClient.getQueryData<Rule[]>(key)
      queryClient.setQueryData<Rule[]>(key, (current) =>
        current?.map((item) => (item.id === rule.id ? { ...item, enabled } : item))
      )
      return { previous }
    },
    onError: (error: Error, _variables, context) => {
      if (context?.previous) {
        queryClient.setQueryData(queryKeys.rules(zoneId), context.previous)
      }
      toast.error("Could not update rule", { description: error.message })
    },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.rules(zoneId) })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (rule: Rule) => apiClient.deleteRule(rule.id, zoneId),
    onSuccess: async () => {
      toast.success("Routing rule deleted")
      setDeleteTarget(null)
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.rules(zoneId) }),
        queryClient.invalidateQueries({ queryKey: queryKeys.inboxSummary }),
      ])
    },
    onError: (error: Error) => {
      toast.error("Could not delete rule", { description: error.message })
    },
  })

  const copyRuleEmail = (rule: Rule) => {
    const email = ruleEmail(rule)
    void copyText(email)
      .then(() => toast.success("Address copied", { description: email }))
      .catch(() => toast.error("Could not copy address"))
  }

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Email routing"
        title="Routing rules"
        description="Literal addresses, routed exactly where you want. Toggle rules instantly — changes apply in real time."
        actions={
          <>
            <Button
              variant="outline"
              onClick={() => void rulesQuery.refetch()}
              disabled={!zoneId || rulesQuery.isFetching}
            >
              <RefreshCw className={cn(rulesQuery.isFetching && "animate-spin")} />
              Refresh
            </Button>
            <Button onClick={() => setCreateOpen(true)} disabled={!domains.length}>
              <Plus />
              New rule
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
        <StatCard label="Rules" value={rules.length} icon={Route} hint={selectedDomain?.name || "No domain"} />
        <StatCard label="Active" value={enabledCount} icon={Zap} accent="blue" hint="Currently routing" />
        <StatCard label="To workers" value={workerCount} icon={Cpu} accent="violet" hint="Inbox delivery" />
        <StatCard label="Forwarding" value={forwardCount} icon={Send} accent="amber" hint="To destinations" />
      </div>

      <div className="surface-card overflow-hidden rounded-2xl">
        <div className="flex flex-col gap-3 border-b border-border/60 p-3 sm:flex-row sm:items-center">
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-medium tracking-[0.12em] text-muted-foreground uppercase">
              Zone
            </span>
            <Select
              value={zoneId || undefined}
              onValueChange={(value) => setZoneId(String(value || ""))}
              disabled={domainsLoading || !domains.length}
            >
              <SelectTrigger className="h-9 min-w-44" aria-label="Zone">
                <SelectValue>
                  {(value) =>
                    domains.find((domain) => domain.id === value)?.name ??
                    (domainsLoading ? "Loading…" : "Select domain")
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
          </div>

          <div className="flex flex-1 flex-col gap-2 sm:flex-row sm:items-center sm:justify-end">
            <div className="relative w-full sm:max-w-56">
              <Search className="pointer-events-none absolute top-1/2 left-3 size-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search rules…"
                className="h-9 bg-background/60 pl-8"
                aria-label="Search rules"
              />
            </div>
            <div className="flex rounded-lg bg-muted/60 p-0.5">
              {(["all", "active", "paused"] as const).map((value) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => setFilter(value)}
                  className={cn(
                    "rounded-md px-2.5 py-1.5 text-[11px] font-medium capitalize transition-colors",
                    filter === value
                      ? "bg-background text-foreground shadow-sm"
                      : "text-muted-foreground hover:text-foreground"
                  )}
                >
                  {value}
                </button>
              ))}
            </div>
          </div>
        </div>

        {domainsError ? (
          <div className="p-4">
            <ErrorState
              title="Domains unavailable"
              message={domainsError.message}
              onRetry={() => void queryClient.invalidateQueries({ queryKey: queryKeys.domains })}
            />
          </div>
        ) : !domains.length && !domainsLoading ? (
          <EmptyState
            icon={Mail}
            title="No zones connected"
            description="Add your Cloudflare credentials and make sure the token has Email Routing access."
            action={
              <Button variant="outline" size="sm" onClick={() => navigate("/settings")}>
                <Settings2 />
                Open settings
              </Button>
            }
          />
        ) : rulesQuery.isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 5 }).map((_, index) => (
              <Skeleton key={index} className="h-16 rounded-xl" />
            ))}
          </div>
        ) : rulesQuery.error ? (
          <div className="p-4">
            <ErrorState
              title="Could not load routing rules"
              message={rulesQuery.error.message}
              onRetry={() => void rulesQuery.refetch()}
            />
          </div>
        ) : filtered.length ? (
          <div className="divide-y divide-border/60">
            {filtered.map((rule, index) => {
              const action = ruleAction(rule)
              const email = ruleEmail(rule)
              return (
                <motion.div
                  key={rule.id}
                  initial={prefersReducedMotion ? false : { opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{
                    duration: 0.3,
                    delay: Math.min(index, 10) * 0.03,
                    ease: [0.22, 1, 0.36, 1],
                  }}
                  className="group flex flex-col gap-3 px-3 py-3 transition-colors hover:bg-muted/30 sm:flex-row sm:items-center sm:px-4"
                >
                  <div
                    className={cn(
                      "grid size-9 shrink-0 place-items-center rounded-xl",
                      action.type === "worker"
                        ? "bg-violet-500/10 text-violet-600 dark:text-violet-400"
                        : action.type === "forward"
                          ? "bg-sky-500/10 text-sky-600 dark:text-sky-400"
                          : "bg-muted text-muted-foreground"
                    )}
                  >
                    <ActionIcon type={action.type} />
                  </div>

                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="truncate font-mono text-[13px] font-medium" title={email}>
                        {email}
                      </p>
                      <Badge
                        variant="secondary"
                        className={cn(
                          "text-[10px] capitalize",
                          rule.enabled
                            ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                            : "bg-muted text-muted-foreground"
                        )}
                      >
                        {rule.enabled ? "Active" : "Paused"}
                      </Badge>
                    </div>
                    <p className="mt-1 flex flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground">
                      <Badge variant="outline" className="gap-1 text-[10px] capitalize">
                        <ActionIcon type={action.type} />
                        {action.type}
                      </Badge>
                      <ArrowRight className="size-3" />
                      <span className="truncate">{action.value}</span>
                      {rule.priority !== undefined && (
                        <>
                          <span className="text-border">·</span>
                          <span>priority {rule.priority}</span>
                        </>
                      )}
                    </p>
                  </div>

                  <div className="flex items-center gap-1.5 sm:shrink-0">
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      onClick={() => copyRuleEmail(rule)}
                      aria-label={`Copy ${email}`}
                      title="Copy address"
                    >
                      <Copy />
                    </Button>
                    {email.includes("@") && (
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        onClick={() => {
                          setActiveAddress(email)
                          navigate("/inbox")
                        }}
                        aria-label="Open inbox"
                        title="Open inbox"
                      >
                        <Inbox />
                      </Button>
                    )}
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      className="text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                      onClick={() => setDeleteTarget(rule)}
                      aria-label={`Delete rule for ${email}`}
                    >
                      <Trash2 />
                    </Button>
                    <Switch
                      checked={Boolean(rule.enabled)}
                      onCheckedChange={(checked) =>
                        toggleMutation.mutate({ rule, enabled: checked })
                      }
                      disabled={toggleMutation.isPending}
                      aria-label={`${rule.enabled ? "Pause" : "Enable"} rule for ${email}`}
                    />
                  </div>
                </motion.div>
              )
            })}
          </div>
        ) : (
          <EmptyState
            icon={Route}
            title={search || filter !== "all" ? "No rules match" : "No routing rules"}
            description={
              search || filter !== "all"
                ? "Adjust the search or filter to see more rules."
                : `Create a literal address on ${selectedDomain?.name || "this domain"} to start routing mail.`
            }
            action={
              search || filter !== "all" ? (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setSearch("")
                    setFilter("all")
                  }}
                >
                  Clear filters
                </Button>
              ) : (
                <Button size="sm" onClick={() => setCreateOpen(true)}>
                  <Plus />
                  New rule
                </Button>
              )
            }
          />
        )}
      </div>

      <CreateRuleDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        domainId={zoneId}
        domainName={selectedDomain?.name || ""}
        workers={workers}
        destinations={destinationsQuery.data ?? []}
        destinationsError={destinationsQuery.error as Error | null}
        onCreated={() => {
          void queryClient.invalidateQueries({ queryKey: queryKeys.rules(zoneId) })
        }}
      />

      <AlertDialog open={Boolean(deleteTarget)} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete this routing rule?</AlertDialogTitle>
            <AlertDialogDescription>
              {deleteTarget
                ? `Mail to ${ruleEmail(deleteTarget)} will no longer follow this rule. This cannot be undone.`
                : ""}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget)}
              disabled={deleteMutation.isPending}
              className="bg-destructive text-white hover:bg-destructive/90"
            >
              {deleteMutation.isPending ? <Loader2 className="animate-spin" /> : <Trash2 />}
              Delete rule
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

type CreateRuleDialogProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
  domainId: string
  domainName: string
  workers: { id: string; name: string }[]
  destinations: Destination[]
  destinationsError: Error | null
  onCreated: () => void
}

function CreateRuleDialog({
  open,
  onOpenChange,
  domainId,
  domainName,
  workers,
  destinations,
  destinationsError,
  onCreated,
}: CreateRuleDialogProps) {
  const [localPart, setLocalPart] = React.useState("")
  const [actionType, setActionType] = React.useState<"worker" | "forward" | "drop">("worker")
  const [destination, setDestination] = React.useState("")
  const [error, setError] = React.useState("")

  const defaultWorker =
    workers.find((worker) => /inbox/i.test(worker.name || "")) ?? workers[0] ?? null

  React.useEffect(() => {
    if (!open) return
    setActionType("worker")
    setDestination(defaultWorker?.name || "")
    setError("")
  }, [defaultWorker?.name, open])

  const createMutation = useMutation({
    mutationFn: () =>
      apiClient.createRule({
        customEmail: `${localPart.trim()}@${domainName}`.toLowerCase(),
        type: actionType,
        destinationIdManual: actionType === "worker" ? destination : undefined,
        destinationId: actionType === "forward" ? destination : undefined,
        zoneId: domainId,
      }),
    onSuccess: () => {
      toast.success("Routing rule created", {
        description: `${localPart.trim()}@${domainName}`,
      })
      onCreated()
      onOpenChange(false)
      setLocalPart("")
      setError("")
    },
    onError: (mutationError: Error) => {
      setError(mutationError.message)
    },
  })

  const submit = (event: React.FormEvent) => {
    event.preventDefault()
    if (!localPart.trim()) {
      setError("Enter the part before @.")
      return
    }
    if (/\s|@/.test(localPart.trim())) {
      setError("The name cannot contain spaces or @.")
      return
    }
    if (actionType !== "drop" && !destination) {
      setError(
        actionType === "worker"
          ? "Select a worker to deliver mail to."
          : "Select a verified destination."
      )
      return
    }
    if (!domainId || !domainName) {
      setError("Select a domain first.")
      return
    }
    setError("")
    createMutation.mutate()
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-[calc(100%-1.5rem)] gap-0 overflow-hidden p-0 sm:max-w-lg">
        <div className="relative overflow-hidden border-b border-border/70 bg-muted/35 px-5 pt-5 pb-4">
          <div className="pointer-events-none absolute -top-16 -right-10 size-40 rounded-full bg-primary/15 blur-3xl" />
          <DialogHeader className="relative">
            <DialogTitle className="text-lg">Create a routing rule</DialogTitle>
            <DialogDescription className="mt-1 text-[13px]">
              Route a literal address on{" "}
              <span className="font-medium text-foreground">{domainName || "your domain"}</span>{" "}
              to a worker, a verified destination, or drop it.
            </DialogDescription>
          </DialogHeader>
        </div>

        <form onSubmit={submit} className="space-y-5 p-5">
          <div className="space-y-2">
            <Label htmlFor="rule-local-part">Address</Label>
            <div className="flex items-center gap-2">
              <Input
                id="rule-local-part"
                value={localPart}
                onChange={(event) => {
                  setLocalPart(event.target.value)
                  setError("")
                }}
                placeholder="hello"
                className="font-mono text-[13px]"
                autoFocus
              />
              <span className="shrink-0 font-mono text-[12px] text-muted-foreground">
                @{domainName || "domain"}
              </span>
            </div>
          </div>

          <div className="space-y-2">
            <Label>Action</Label>
            <div className="grid grid-cols-3 gap-2">
              {(
                [
                  { value: "worker", label: "Worker", icon: Cpu },
                  { value: "forward", label: "Forward", icon: Send },
                  { value: "drop", label: "Drop", icon: Trash2 },
                ] as const
              ).map((option) => {
                const Icon = option.icon
                const active = actionType === option.value
                return (
                  <button
                    key={option.value}
                    type="button"
                    onClick={() => {
                      setActionType(option.value)
                      setError("")
                      if (option.value === "worker") {
                        setDestination(defaultWorker?.name || "")
                      } else if (option.value === "forward") {
                        setDestination(destinations[0]?.email || "")
                      } else {
                        setDestination("")
                      }
                    }}
                    className={cn(
                      "flex flex-col items-center gap-1.5 rounded-xl border p-3 text-[11px] font-medium transition-colors",
                      active
                        ? "border-primary/30 bg-primary/8 text-primary"
                        : "border-border/70 text-muted-foreground hover:bg-muted/50 hover:text-foreground"
                    )}
                  >
                    <Icon className="size-4" />
                    {option.label}
                  </button>
                )
              })}
            </div>
          </div>

          {actionType !== "drop" && (
            <div className="space-y-2">
              <Label>{actionType === "worker" ? "Worker" : "Destination"}</Label>
              <Select
                value={destination || undefined}
                onValueChange={(value) => {
                  setDestination(String(value || ""))
                  setError("")
                }}
              >
                <SelectTrigger className="w-full" aria-label="Destination">
                  <SelectValue placeholder="Select a destination">
                    {(value) =>
                      actionType === "worker"
                        ? workers.find((worker) => worker.name === value)?.name ||
                          "Select a worker"
                        : destinations.find((item) => item.email === value)?.email ||
                          "Select a destination"
                    }
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  {actionType === "worker"
                    ? workers.map((worker) => (
                        <SelectItem key={worker.id} value={worker.name}>
                          {worker.name}
                          {/inbox/i.test(worker.name) ? " (inbox)" : ""}
                        </SelectItem>
                      ))
                    : destinations.map((item) => (
                        <SelectItem key={item.id} value={item.email}>
                          {item.email}
                          {item.verified === false ? " (unverified)" : ""}
                        </SelectItem>
                      ))}
                </SelectContent>
              </Select>
              {actionType === "worker" && !workers.length && (
                <p className="text-[11px] text-amber-600 dark:text-amber-400">
                  No workers found. The panel will fall back to{" "}
                  <span className="font-mono">inbox-worker</span>.
                </p>
              )}
              {actionType === "forward" && !destinations.length && (
                <p className="text-[11px] text-amber-600 dark:text-amber-400">
                  {destinationsError
                    ? destinationsError.message
                    : "No destinations yet. Add one in Destinations first."}
                </p>
              )}
            </div>
          )}

          {actionType === "drop" && (
            <div className="rounded-xl border border-border/70 bg-muted/35 p-3 text-[12px] text-muted-foreground">
              Messages sent to this address will be accepted and silently discarded — no forward,
              no inbox copy.
            </div>
          )}

          {error && (
            <p role="alert" className="text-xs font-medium text-destructive">
              {error}
            </p>
          )}

          <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={createMutation.isPending || !domainName}>
              {createMutation.isPending ? <Loader2 className="animate-spin" /> : <Check />}
              {createMutation.isPending ? "Creating…" : "Create rule"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  )
}

